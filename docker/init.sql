-- Create a non-superuser role for the application.
-- Superusers bypass RLS even with FORCE ROW LEVEL SECURITY.
-- The app must connect as a non-superuser for RLS to be enforced.
CREATE USER getlicense WITH PASSWORD 'getlicense';
GRANT ALL PRIVILEGES ON DATABASE getlicense TO getlicense;
\c getlicense
GRANT ALL ON SCHEMA public TO getlicense;
