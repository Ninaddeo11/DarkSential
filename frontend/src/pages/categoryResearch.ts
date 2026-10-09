export interface ResearchBrief {
  introduction: string;
  photo: string;
  photoAlt: string;
  signals: [string, string][];
  logs: [string, string][];
  questions: string[];
}

export const CATEGORY_RESEARCH: Record<string, ResearchBrief> = {
  'dark-web': {
    introduction: 'Build a timeline from collected mentions, archived pages and corroborated indicators. A post is a claim until its source, context and supporting evidence have been reviewed.',
    photo: 'security', photoAlt: 'Computer screens and equipment in a dark technology workspace',
    signals: [['Brand and domain mentions', 'Look for organization names, email domains and product references. Preserve surrounding text to distinguish a target mention from a quoted news story.'], ['Repeated artifacts', 'Compare file hashes, public contact handles and infrastructure indicators across collected material. Repeated wording alone does not establish a common operator.'], ['Changes in claims', 'Track edited posts, changed timestamps and disappearing references. Record what changed and when your collector observed it.']],
    logs: [['Archived source captures', 'Review capture timestamps, source identifiers, content hashes and collection status. Compare the earliest available snapshot with later versions.'], ['Mention history', 'Review previous matches, analyst dispositions and false positives before escalating a new mention.'], ['Collection health', 'Check failed fetches, parser changes and collection gaps. A missing observation may reflect a collection failure.']],
    questions: ['Can the original capture be traced to its source?', 'Is the claim supported by independently collected evidence?', 'Does the timeline separate publication time from observation time?'],
  },
  malware: {
    introduction: 'Connect a suspicious file to observed behavior, affected assets and related indicators. Use hashes and execution evidence to separate an actual detection from an unverified family label.',
    photo: 'security', photoAlt: 'Technology equipment and computer screens in a security research setting',
    signals: [['Unexpected execution', 'Review unfamiliar parent-child process relationships, unusual command lines and execution from temporary directories against the asset baseline.'], ['Persistence changes', 'Investigate newly observed services, scheduled tasks and startup entries. Connect each change to an account and process where available.'], ['Outbound communication', 'Correlate suspicious destinations with DNS lookups, process telemetry and repeated connection patterns. Shared hosting can create unrelated matches.']],
    logs: [['Endpoint detection history', 'Compare file hashes, detection names, quarantine outcomes and affected hosts with previous alerts.'], ['Process and file events', 'Reconstruct the sequence from file creation to execution, persistence and attempted network access. Preserve the original timestamps.'], ['DNS and proxy history', 'Look for prior destination contacts, blocked requests and connections before and after containment.']],
    questions: ['Was the sample executed or only present on disk?', 'Which assets show matching behavior?', 'Is containment supported by subsequent telemetry?'],
  },
  vulnerabilities: {
    introduction: 'Prioritize findings through asset exposure, affected versions and observed exploitation evidence. A vulnerability entry becomes actionable when it is connected to an actual system and owner.',
    photo: 'code', photoAlt: 'Source code displayed on a computer screen',
    signals: [['Affected software', 'Match the reported product and version against inventory. Check deployment-specific conditions rather than relying on a product name alone.'], ['Exposure and ownership', 'Identify reachable services, business importance and the team responsible for remediation.'], ['Exploitation evidence', 'Correlate suspicious requests and endpoint changes with the finding. A scanner result alone does not prove compromise.']],
    logs: [['Scan history', 'Compare first detection, recurring findings, scan coverage and previously accepted exceptions.'], ['Patch and change records', 'Review deployment dates, maintenance outcomes and verification scans to confirm whether remediation reached the affected assets.'], ['Application and access logs', 'Inspect suspicious request patterns around the exposure window and correlate with host events.']],
    questions: ['Is the installed version actually affected?', 'Has the remediation been verified?', 'Are there signs of activity during the exposure window?'],
  },
  actors: {
    introduction: 'Build actor hypotheses from documented behavior and independently supported relationships. Keep observed activity separate from names, aliases and attribution judgments.',
    photo: 'security', photoAlt: 'Computer workspace illustrating digital threat research',
    signals: [['Behavioral overlap', 'Compare recurring techniques, target patterns and sequences of activity. Similar techniques can be used by unrelated groups.'], ['Alias relationships', 'Record who asserted an alias connection, when it was published and the evidence behind it.'], ['Infrastructure reuse', 'Review shared indicators alongside time ranges and ownership changes before linking campaigns.']],
    logs: [['Campaign chronology', 'Compare first and last observations, targeted assets and changes in activity across documented campaigns.'], ['Attribution revisions', 'Review previous assessments, confidence changes and contradictory findings.'], ['Relationship evidence', 'Trace each actor-to-indicator or actor-to-malware link back to its source and observation date.']],
    questions: ['Which relationships are observed and which are inferred?', 'Could shared tools explain the overlap?', 'What evidence would change the attribution assessment?'],
  },
  identities: {
    introduction: 'Review identity exposure through account history, authentication evidence and verified associations. Similar usernames or profile images are leads, not proof of a shared identity.',
    photo: 'code', photoAlt: 'Computer display representing digital account and identity research',
    signals: [['Account anomalies', 'Compare unusual sign-ins, new devices and privilege changes against the account baseline.'], ['Exposed identifiers', 'Track mentions of organization email domains and account names without reproducing passwords or unnecessary personal information.'], ['Unverified associations', 'Document the evidence behind handle, email and account relationships. Keep uncertain matches separate.']],
    logs: [['Authentication history', 'Review successful and failed sign-ins, session creation and multi-factor events around the suspected exposure.'], ['Account lifecycle', 'Inspect provisioning, access grants, password resets and deactivation records.'], ['Prior exposure reviews', 'Compare earlier alerts, verified ownership and resolution notes to avoid repeatedly escalating the same material.']],
    questions: ['Is ownership of the account verified?', 'Was access attempted or confirmed?', 'What personal data is necessary for the investigation?'],
  },
  crypto: {
    introduction: 'Review publicly recorded transactions and source-backed address associations. Ledger activity can establish transfers; it does not by itself establish the identity or intent of an owner.',
    photo: 'crypto', photoAlt: 'Physical Bitcoin tokens used as an illustration of cryptocurrency research',
    signals: [['Address references', 'Preserve the source that associates an address with a claim, incident or entity. Distinguish a published association from verified ownership.'], ['Transaction context', 'Review transaction identifiers, chain, asset and block timestamps. Similar-looking addresses on different networks need separate treatment.'], ['Timing relationships', 'Compare documented incident windows with transaction observations while recording alternative explanations.']],
    logs: [['Transaction history', 'Review public transaction records and observation dates. Preserve the exact network and transaction identifier.'], ['Address annotation changes', 'Check when labels were added, their source and whether an earlier attribution was withdrawn.'], ['Case comparison notes', 'Review prior analyst reasoning and unresolved assumptions before reusing a relationship.']],
    questions: ['Which blockchain and asset does the evidence refer to?', 'Is the ownership claim independently supported?', 'Can every reported transfer be reproduced from its public record?'],
  },
  trafficking: {
    introduction: 'Study documented patterns and associations through lawful reporting and preserved evidence. Keep the focus on corroboration, safeguarding and accountable case review.',
    photo: 'logistics', photoAlt: 'Shipping containers illustrating the infrastructure context of logistics research',
    signals: [['Repeated documented associations', 'Compare recurring organizations, identifiers and communication references across authorized case material.'], ['Inconsistent documentation', 'Record discrepancies between source accounts and preserved records without treating a discrepancy as proof of criminal activity.'], ['Safeguarding indicators', 'Flag documented signs of coercion or exploitation for qualified review. Minimize identifying information about vulnerable people.']],
    logs: [['Case chronology', 'Review earlier referrals, observation dates and corroboration notes to understand the sequence of documented events.'], ['Source and custody records', 'Check evidence origin, collection authority and recorded handling history.'], ['Review and referral history', 'Trace prior assessments, unresolved questions and actions already taken by authorized teams.']],
    questions: ['Are the source accounts independently corroborated?', 'Does the record distinguish allegation from finding?', 'Have identifying details been limited to those necessary for authorized review?'],
  },
  infrastructure: {
    introduction: 'Connect domains, addresses and services to time-bounded observations. Infrastructure ownership and hosting can change, so relationships need dates and supporting evidence.',
    photo: 'servers', photoAlt: 'Rows of server equipment in a data center',
    signals: [['DNS changes', 'Compare new resolutions, changed records and unusual subdomains with historical observations.'], ['Certificate relationships', 'Review certificate metadata and observed service connections. A shared issuer or hosting provider is not sufficient to link operators.'], ['Endpoint behavior', 'Correlate service exposure and destination contacts with observed events on monitored assets.']],
    logs: [['DNS observation history', 'Review first and last sightings, record values and the collector that observed each answer.'], ['Network connection logs', 'Compare source hosts, destinations, ports and time windows to establish which assets actually communicated.'], ['Service and certificate history', 'Inspect changes in exposed services, certificates and hosting alongside documented ownership changes.']],
    questions: ['Was the relationship valid at the time of the incident?', 'Could shared infrastructure explain the association?', 'Which internal assets contacted the indicator?'],
  },
  weapons: {
    introduction: 'Review weapons-related claims as evidence research using authorized records and verified reporting. Separate claimed listings, reused imagery and documented findings.',
    photo: 'logistics', photoAlt: 'Container infrastructure providing a contextual logistics photograph',
    signals: [['Image reuse', 'Compare image provenance and previous appearances. A reused photograph can undermine a claim without identifying the source of the pictured object.'], ['Claim inconsistencies', 'Record conflicting descriptions, dates and source statements for qualified review.'], ['Documented associations', 'Link identifiers only where an authorized source supports the relationship and preserve its confidence level.']],
    logs: [['Archived claims', 'Review previous captures, changed descriptions and the dates each claim was observed.'], ['Evidence provenance', 'Check original source files, hashes and handling records rather than relying on cropped or reposted images.'], ['Prior case assessments', 'Inspect earlier dispositions, unresolved claims and independent corroboration.']],
    questions: ['Does the image have a verifiable origin?', 'Is the claim independently supported?', 'Is the assessment clearly separated from an allegation?'],
  },
  narcotics: {
    introduction: 'Examine narcotics-related reporting through preserved evidence, authorized case records and verified findings. Claimed substances and visual appearances require specialist confirmation.',
    photo: 'logistics', photoAlt: 'Shipping containers providing context for evidence and consignment research',
    signals: [['Repeated evidence references', 'Compare documented identifiers and source references across authorized records. Avoid assuming similar packaging implies a common source.'], ['Unverified substance claims', 'Record a claimed description separately from any verified laboratory or official finding.'], ['Changes across captures', 'Review edited imagery, descriptions and dates while preserving the original records.']],
    logs: [['Case and consignment records', 'Review lawful case references, recorded observations and previous analyst assessments.'], ['Laboratory and evidence history', 'Where authorized, distinguish preliminary descriptions from confirmed findings and retain their source.'], ['Custody and review records', 'Trace evidence handling, review dates and outstanding questions to maintain an accountable record.']],
    questions: ['Is the substance description claimed or verified?', 'Can the evidence be traced through its handling history?', 'Which associations are supported by independent records?'],
  },
};
