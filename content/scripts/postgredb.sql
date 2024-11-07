
CREATE TABLE IF NOT EXISTS public.ca (
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
CREATE TABLE IF NOT EXISTS public.certificates (
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

CREATE TABLE IF NOT EXISTS public.crl (
	"caSerial" varchar(250) NOT NULL,
	"number" integer NOT NULL,
	"issueDate" timestamp with time zone NOT NULL,
	"expireDate" timestamp with time zone NOT NULL,
	"lastSerial" varchar(250) NULL,
	"content" bytea NOT NULL,
	CONSTRAINT crl_pk PRIMARY KEY ("caSerial","number")
);
