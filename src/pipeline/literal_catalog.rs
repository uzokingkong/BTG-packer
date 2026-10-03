//! Read-only literal inventory. Approval is not proof that encryption occurred.
//! This module deliberately performs no file export or payload mutation.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Ascii,
    Utf8,
    Utf16Le,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPhase {
    Loader,
    PreBootTls,
    Bootstrap,
    PostBoot,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    ExplicitMap,
    VerifiedReference,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralSpan {
    pub id: u64,
    pub rva: u32,
    /// Payload length in bytes, excluding the owned terminator.
    pub byte_len: u32,
    pub terminator_len: u8,
    pub encoding: Encoding,
    pub phase: AccessPhase,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    LoaderAccess,
    PreBootTlsAccess,
    BootstrapAccess,
    UnknownAccess,
    MissingEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Eligible,
    Exclude(Reason),
    RequireAnnotation(Reason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub span: LiteralSpan,
    pub decision: Decision,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiteralCatalog {
    entries: Vec<CatalogEntry>,
}

impl LiteralCatalog {
    /// Validates object-level invariants. PE mapping and encoding validation
    /// must additionally be performed by the map ingestion layer.
    pub fn from_spans(mut spans: Vec<LiteralSpan>) -> Result<Self, &'static str> {
        spans.sort_by_key(|s| (s.rva, s.id));
        let mut ids = BTreeSet::new();
        let mut previous_end = 0u64;
        let mut entries = Vec::with_capacity(spans.len());
        for span in spans {
            if !ids.insert(span.id) {
                return Err("duplicate literal id");
            }
            if span.byte_len == 0 {
                return Err("empty literal span");
            }
            let valid_terminator = match span.encoding {
                Encoding::Ascii | Encoding::Utf8 => {
                    span.terminator_len == 0 || span.terminator_len == 1
                }
                Encoding::Utf16Le => {
                    span.byte_len % 2 == 0 && (span.terminator_len == 0 || span.terminator_len == 2)
                }
            };
            if !valid_terminator {
                return Err("invalid encoding length or terminator size");
            }
            let end =
                u64::from(span.rva) + u64::from(span.byte_len) + u64::from(span.terminator_len);
            if end > u64::from(u32::MAX) + 1 {
                return Err("literal RVA range overflow");
            }
            if u64::from(span.rva) < previous_end {
                return Err("overlapping literal ownership");
            }
            previous_end = end;
            let decision = match span.phase {
                AccessPhase::Loader => Decision::Exclude(Reason::LoaderAccess),
                AccessPhase::PreBootTls => Decision::Exclude(Reason::PreBootTlsAccess),
                AccessPhase::Bootstrap => Decision::Exclude(Reason::BootstrapAccess),
                AccessPhase::Unknown => Decision::RequireAnnotation(Reason::UnknownAccess),
                AccessPhase::PostBoot => match span.evidence {
                    Evidence::Heuristic => Decision::RequireAnnotation(Reason::MissingEvidence),
                    Evidence::ExplicitMap | Evidence::VerifiedReference => Decision::Eligible,
                },
            };
            entries.push(CatalogEntry { span, decision });
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// Aggregate-only view: contains no literal bytes, RVAs, or object IDs.
    pub fn summary(&self) -> CatalogSummary {
        let mut summary = CatalogSummary::default();
        for entry in &self.entries {
            summary.candidates += 1;
            match entry.decision {
                Decision::Eligible => summary.eligible += 1,
                Decision::Exclude(_) => summary.excluded += 1,
                Decision::RequireAnnotation(_) => summary.require_annotation += 1,
            }
        }
        summary
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatalogSummary {
    pub candidates: usize,
    pub eligible: usize,
    pub excluded: usize,
    pub require_annotation: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(id: u64, rva: u32) -> LiteralSpan {
        LiteralSpan {
            id,
            rva,
            byte_len: 3,
            terminator_len: 1,
            encoding: Encoding::Utf8,
            phase: AccessPhase::PostBoot,
            evidence: Evidence::ExplicitMap,
        }
    }

    #[test]
    fn phase_exclusions_override_explicit_map() {
        for (phase, reason) in [
            (AccessPhase::Loader, Reason::LoaderAccess),
            (AccessPhase::PreBootTls, Reason::PreBootTlsAccess),
            (AccessPhase::Bootstrap, Reason::BootstrapAccess),
        ] {
            let mut s = span(1, 100);
            s.phase = phase;
            let catalog = LiteralCatalog::from_spans(vec![s]).unwrap();
            assert_eq!(catalog.entries()[0].decision, Decision::Exclude(reason));
        }
    }

    #[test]
    fn unknown_and_heuristic_require_annotation() {
        let mut unknown = span(1, 100);
        unknown.phase = AccessPhase::Unknown;
        let mut heuristic = span(2, 104);
        heuristic.evidence = Evidence::Heuristic;
        let catalog = LiteralCatalog::from_spans(vec![heuristic, unknown, span(3, 108)]).unwrap();
        assert_eq!(
            catalog.summary(),
            CatalogSummary {
                candidates: 3,
                eligible: 1,
                excluded: 0,
                require_annotation: 2
            }
        );
        assert_eq!(catalog.entries()[0].span.id, 1);
    }

    #[test]
    fn ownership_includes_terminator() {
        assert!(LiteralCatalog::from_spans(vec![span(1, 100), span(2, 103)]).is_err());
        assert!(LiteralCatalog::from_spans(vec![span(1, 100), span(2, 104)]).is_ok());
    }

    #[test]
    fn rejects_duplicate_ids_overflow_and_bad_lengths() {
        assert!(LiteralCatalog::from_spans(vec![span(1, 100), span(1, 104)]).is_err());
        assert!(LiteralCatalog::from_spans(vec![span(1, u32::MAX - 1)]).is_err());
        let mut s = span(1, 100);
        s.encoding = Encoding::Utf16Le;
        s.terminator_len = 2;
        assert!(LiteralCatalog::from_spans(vec![s.clone()]).is_err());
        s.byte_len = 4;
        assert!(LiteralCatalog::from_spans(vec![s.clone()]).is_ok());
        s.byte_len = 0;
        assert!(LiteralCatalog::from_spans(vec![s]).is_err());
    }
}
