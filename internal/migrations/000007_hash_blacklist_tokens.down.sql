-- A hash cannot be turned back into a token. Hashed rows stay as they are; the
-- previous release will not match them, which only matters for tokens that are
-- still unexpired at the moment of a rollback.
SELECT 1;
