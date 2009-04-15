-- This is a sample for a table storing unix users
-- pam-pgsql

-- William Grzybowski <william@agencialivre.com.br>

begin;

	CREATE TABLE account (

		username varchar(255) UNIQUE NOT NULL,
		password varchar(200),
		expired boolean,
		newtok boolean

	);

end;
