-- Migrate status of old signing keyshares to be in-use so we no longer need to specify it
-- in query lookups.
UPDATE signing_keyshares
SET status = 'IN_USE', update_time = NOW()
WHERE id <= uuid('01954639-8d50-7e47-b3f0-ddb307fab7c2') AND status != 'IN_USE';
