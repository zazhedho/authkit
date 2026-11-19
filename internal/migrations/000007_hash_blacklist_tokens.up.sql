-- The blacklist stores the hex sha256 of a token, not the token. Existing rows
-- are converted so tokens revoked before this migration stay revoked.
UPDATE blacklist SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex') WHERE length(token) <> 64;
