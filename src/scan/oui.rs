use crate::model::MacAddr;
use std::sync::OnceLock;

static DB: OnceLock<OuiDb> = OnceLock::new();

#[derive(Debug, Default)]
pub struct OuiDb {
    entries: Vec<(u32, String)>,
}

impl OuiDb {
    pub fn load() -> &'static Self {
        DB.get_or_init(|| Self::parse(include_str!("../../assets/oui.dat")))
    }

    pub fn parse(text: &str) -> Self {
        let mut entries: Vec<(u32, String)> = text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let (hex, name) = line.split_once('\t')?;
                let oui = u32::from_str_radix(hex.trim(), 16).ok()?;
                let name = name.trim();
                if name.is_empty() {
                    return None;
                }
                Some((oui, name.to_string()))
            })
            .collect();
        entries.sort_by_key(|(oui, _)| *oui);
        entries.dedup_by_key(|(oui, _)| *oui);
        Self { entries }
    }

    pub fn lookup(&self, mac: MacAddr) -> Option<&str> {
        let key = mac.oui24();
        self.entries
            .binary_search_by_key(&key, |(oui, _)| *oui)
            .ok()
            .map(|idx| self.entries[idx].1.as_str())
    }
}

pub fn vendor_for(mac: MacAddr) -> Option<String> {
    OuiDb::load().lookup(mac).map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_binary_search() {
        let db = OuiDb::parse("001122\tAcme\nAABBCC\tGlobex\n");
        assert_eq!(
            db.lookup("00:11:22:33:44:55".parse().unwrap()),
            Some("Acme")
        );
        assert_eq!(
            db.lookup("aa:bb:cc:00:00:01".parse().unwrap()),
            Some("Globex")
        );
        assert_eq!(db.lookup("ff:ff:ff:00:00:00".parse().unwrap()), None);
    }

    #[test]
    fn bundled_snapshot_has_common_vendors() {
        let db = OuiDb::load();
        assert!(
            db.entries.len() > 1_000,
            "expected a committed IEEE OUI snapshot"
        );
    }
}
