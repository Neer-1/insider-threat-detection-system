# Provenance

LITDS is Neer-1's Computer Science final-year dissertation project. It overlaps with the separate A24 AI Agent Development coursework; they are not the same release.

Existing source comments identify reuse/adaptation in `backend/agent_logic/` (analysis, features, anomalies, behavioral profiling, decision/risk/response logic), with database-backed company/device windows and a larger agent/backend/dashboard architecture added in LITDS. The current scoring path is more extensive than A24's flat-event prototype. This is source-based attribution, not an exhaustive authorship or Git-history audit. No additional A24 material was imported for this candidate.

The release copy derives from the previously audited LITDS-only staging checkpoint named `working/A24-LITDS`. That legacy folder name does not merge the A24 repository. Read-only comparison identified earlier release safeguards against the original dissertation source. Original LITDS, its dirty working tree/history, recovery material and prior checkpoints were preserved; no `.git` directory was copied.

Later Codex-assisted work includes prior removal of unsafe demo/CORS/default-secret behavior and tenant checks; this release adds safe initialization/startup, explicit optional-service gates, removal of temporary screenshot overrides, authentication edge handling, a synthetic demo, focused regression coverage and revised documentation. These changes are release preparation, not evidence that the original submitted project had the same safeguards.

Excluded: private `.env`/credentials, actual activity/device logs and databases, backups, forensic/screenshot evidence, academic documents/reports, caches/environments, build/runtime bundles, dataset CSVs, model weights and unnecessary icons/binaries. Synthetic fixtures are generated from code with fictional identifiers and no real account/password. No original material was deleted.

Third-party libraries retain their own licenses; no library source or weights are vendored. Confirm any dissertation publication/attribution obligations at final review. No new ownership, university-permission or collaborator statement is inferred beyond the user's identification of this as their dissertation. Licensing remains undecided; no LICENSE is supplied.
