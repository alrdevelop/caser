-- DROP SCHEMA public;

CREATE SCHEMA public AUTHORIZATION "admin";

COMMENT ON SCHEMA public IS 'standard public schema';
-- public.ca определение

-- Drop table

-- DROP TABLE public.ca;

CREATE TABLE public.ca (
	serial varchar(250) NOT NULL,
	thumbprint varchar(250) NOT NULL,
	certificate bytea NULL,
	privatekey bytea NULL,
	publicurl varchar(500) NOT NULL,
	CONSTRAINT ca_serial_pk PRIMARY KEY (serial),
	CONSTRAINT ca_unique_thumbprint UNIQUE (thumbprint)
);

-- Permissions

ALTER TABLE public.ca OWNER TO "admin";
GRANT ALL ON TABLE public.ca TO "admin";


-- public.certificates определение

-- Drop table

-- DROP TABLE public.certificates;

CREATE TABLE public.certificates (
	serial varchar(250) NOT NULL,
	thumbprint varchar(250) NOT NULL,
	caserial varchar(250) NOT NULL,
	CONSTRAINT certificates_pk PRIMARY KEY (serial),
	CONSTRAINT certificates_unique_thumbprint UNIQUE (thumbprint),
	CONSTRAINT certificates_ca_fk FOREIGN KEY (serial) REFERENCES public.ca(serial)
);

-- Permissions

ALTER TABLE public.certificates OWNER TO "admin";
GRANT ALL ON TABLE public.certificates TO "admin";




-- Permissions

GRANT ALL ON SCHEMA public TO "admin";
GRANT ALL ON SCHEMA public TO public;