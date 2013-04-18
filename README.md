# plainsq-sinatra - Foursquare v2 client for mobile browsers

## Introduction

This is a Ruby/Sinatra version of [PlainSquare](https://github.com/mortonfox/plainsq) for hosting on Heroku, OpenShift, or any webhost on which you can install a Ruby/Sinatra stack.

## Setup Instructions

If you have an Apache+Passenger setup, follow the instructions in
http://stackoverflow.com/questions/3371208/how-to-setup-a-sinatra-app-under-apache-with-passenger to set up the basic folder structure.

1. Create a setup.rb file containing just one line to set up $DATABASE_URL,
e.g.:

    $DATABASE_URL = 'mysql://user:password@localhost/databasename'

For testing purposes, you can use SQLite:

    $DATABASE_URL = 'sqlite://testdb'

2. Run createdb.rb to initialize the sessions table.

And that should be all.
