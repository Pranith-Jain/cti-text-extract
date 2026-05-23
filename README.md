# cti-text-extract

[![CI](https://github.com/pranith84/cti-text-extract/actions/workflows/ci.yml/badge.svg)](https://github.com/pranith84/cti-text-extract/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Synchronous, dependency-free CTI entity extractor. Pulls IoCs, CVEs, threat actors, malware families, and topic tags out of unstructured text — RSS bodies, briefings, dark-web posts, vendor writeups.

Originally built for the threat-intel platform at [pranithjain.com](https://pranithjain.com), extracted here for general reuse.

## Install

```bash
npm install cti-text-extract
```

## Quick start

```ts
import { extract } from 'cti-text-extract';

const result = extract(
  'APT28 Targets European Government Entities',
  'MSTIC observed APT28 (Fancy Bear) exploiting CVE-2023-36884 against europe-gov[.]example. C2 at https://cremshell-c2.xyz/api/report.'
);

console.log(result);
// {
//   iocs: [
//     { type: 'url', value: 'https://cremshell-c2.xyz/api/report' },
//     { type: 'domain', value: 'europe-gov.example' },
//   ],
//   actors: [{ slug: 'apt28', canonical: 'APT28', aliases: ['Fancy Bear', ...], mitreId: 'G0007', matchedAs: 'APT28' }],
//   malware: [],
//   cves: [{ id: 'CVE-2023-36884' }],
//   tags: ['government', 'spear-phishing'],
//   summary: 'MSTIC observed APT28 (Fancy Bear) exploiting CVE-2023-36884 against europe-gov[.]example. C2 at https://cremshell-c2.xyz/api/report.'
// }
```

## API

```ts
extract(title: string, body: string): ExtractedEntities
```

Returns:

```ts
interface ExtractedEntities {
  iocs: ExtractedIoc[];       // ipv4 / ipv6 / domain / url / email / hash
  actors: ExtractedActor[];   // matched against ACTOR_ALIASES (FIN7, APT28, ...)
  malware: ExtractedMalware[];// matched against MALWARE_DICT (Lumma, RedLine, ...)
  cves: ExtractedCve[];       // CVE-YYYY-NNNN pattern
  tags: string[];             // topic tags from INTEL_KEYWORDS (ransomware, infostealer, ...)
  summary: string;            // first ~280 chars of body
}
```

Granular per-type extractors are also exported:

```ts
import { extractIocs, extractCves, extractActors, extractMalware, extractTags, makeSummary } from 'cti-text-extract';
```

Plus the underlying indicator utilities:

```ts
import { detectType, refang, defang, type IndicatorType } from 'cti-text-extract';
```

And the bundled dictionaries (if you want to introspect or augment them):

```ts
import { ACTOR_ALIASES, MALWARE_DICT, INTEL_KEYWORDS } from 'cti-text-extract';
```

## Design choices

- **Synchronous.** No I/O. Runs in any runtime — Workers, Node, browser. Per-invocation cost is microseconds.
- **Refanged.** Indicator values are run through `refang()` first so common defanging (`hxxp://`, `[.]`, `(dot)`, `[at]`) doesn't hide IoCs.
- **Boundary-aware.** Patterns use word-ish boundaries so "RedLine" the malware doesn't match "redlined the doc."
- **Combolist guard.** Credential-pair shapes (`user:password`, `email:password`) are explicitly rejected — they look like IoCs to a naïve regex but are stolen credentials, not infrastructure.
- **No de-duplication across calls.** Each call returns its own list; caller dedupes if needed.
- **No LLM.** Strict regex + dictionary. Recall caps at "what's in the dict + what regex catches"; precision is high.

## Bundled dictionaries

The package ships with three hand-curated dictionaries:

- **`ACTOR_ALIASES`** — ~80 well-known APT clusters and ransomware operators. Each entry carries the canonical name (Mandiant/FireEye preferred), all known aliases, and the MITRE ATT&CK group ID where one exists.
- **`MALWARE_DICT`** — common malware families seen in 2024–2026 reporting (Lumma, RedLine, Vidar, Cobalt Strike, etc.).
- **`INTEL_KEYWORDS`** — topic tags (ransomware, infostealer, supply-chain, etc.).

Dictionaries are derived from open sources (MITRE ATT&CK Groups, MalwareBazaar tags, MISP galaxies, vendor writeups). Public attribution is preserved on each entry where applicable.

If you need to **extend** the dictionaries, the simplest path is to import the bundled list, concat your additions, and re-compile via `compileWordlist` — or fork and PR. Open issues welcome for missing actors / families.

## What it deliberately does not do

- **No web fetching.** Caller passes text in.
- **No STIX serialization.** Pair with [`stix21-builder`](https://github.com/pranith84/stix21-builder) for that.
- **No fuzzy / LLM matching.** Strict regex + dictionary. If you want novel-entity extraction, pair with an LLM step and merge results.
- **No de-fanging output.** IoCs come back in fanged form (`example.com`, `https://...`). Pair with `defang()` if you need to embed them in slide decks or chat clients.

## Testing

```bash
npm test
```

The test suite covers defang round-trips, alias resolution, false-positive boundaries, combolist-shape rejection, and summary truncation. ~30 cases.

## License

MIT — see [LICENSE](LICENSE).

The bundled dictionaries are derived from open public sources; attribution is preserved per-entry where applicable.
