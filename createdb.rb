require 'rubygems'
require 'sequel'
require './setup.rb'

stmt = <<-EOM
CREATE TABLE sessions ( 
  uuid VARCHAR(100) PRIMARY KEY,
  token VARCHAR(100),
  coords VARCHAR(100),
  last_updated TIMESTAMP 
)
EOM

Sequel.connect($DATABASE_URL) { |db|
  db.run stmt
}
