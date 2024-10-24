-- DROP SCHEMA public;

CREATE SCHEMA public AUTHORIZATION "admin";

COMMENT ON SCHEMA public IS 'standard public schema';
-- public.ca определение

-- Drop tables
DROP TABLE public.certificates;
DROP TABLE public.ca;



CREATE TABLE public.ca (
	"serial" varchar(250) NOT NULL,
	"thumbprint" varchar(250) NOT NULL,
	"commonName" varchar(500) NOT NULL,
	"issueDate" timestamp with time zone NOT NULL,
	"certificate" bytea NOT NULL,
	"privateKey" bytea NOT NULL,
	"publicUrl" varchar(500) NOT NULL,
	CONSTRAINT ca_serial_pk PRIMARY KEY ("serial"),
	CONSTRAINT ca_unique_thumbprint UNIQUE ("thumbprint")
);

-- Permissions

ALTER TABLE public.ca OWNER TO "admin";
GRANT ALL ON TABLE public.ca TO "admin";


-- public.certificates определение


CREATE TABLE public.certificates (
	"serial" varchar(250) NOT NULL,
	"thumbprint" varchar(250) NOT NULL,
	"caSerial" varchar(250) NOT NULL,
	"commonName" varchar(500) NOT NULL,
	"issueDate" timestamp with time zone NOT NULL,
	"revokeDate" timestamp with time zone NULL,
	CONSTRAINT certificates_pk PRIMARY KEY ("serial"),
	CONSTRAINT certificates_unique_thumbprint UNIQUE ("thumbprint"),
	CONSTRAINT certificates_ca_fk FOREIGN KEY ("caSerial") REFERENCES public.ca("serial")
);

-- Permissions

ALTER TABLE public.certificates OWNER TO "admin";
GRANT ALL ON TABLE public.certificates TO "admin";




-- Permissions

GRANT ALL ON SCHEMA public TO "admin";
GRANT ALL ON SCHEMA public TO public;