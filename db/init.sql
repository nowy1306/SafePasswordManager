create table accounts(
	id int not null auto_increment primary key,
    login varchar(30) not null,
	password varchar(60) not null,
	firstname varchar(30) not null,
	lastname varchar(30) not null,
	email varchar(30) not null,
	failed_login_attempts int not null default 0
);

create table passwords(
	id int not null auto_increment primary key,
    account_id int not null,
    description varchar(128) not null,
	password varchar(128) not null,
	nonce varchar(128) not null,
	tag varchar(128) not null,
	foreign key (account_id) REFERENCES accounts(id)
);