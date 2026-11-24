ADDED: `sqlite` feature (on by default); without it, `rusqlite` is not a dependency
ADDED: experimental `custom-store` feature: public `storage` module, `DirMgrExtensions::store_opener`
ADDED: `Error::ExternalStore`
BREAKING: `Error::SqliteError` exists only with the `sqlite` feature
