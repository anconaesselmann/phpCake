# phpCake

phpCake A simple backend for home automation for the Raspberry Pi.

## Routes supported:

### /home
Returns information about the home:
- urn: A unique identifier for the home
- name: The display name for the home
- url_remote: URL for accessing the home from anywhere
- url_local: URL for accessing the home when connected to the local wifi (in progress: some actions can only be executed when connected to the loca wifi)

### /login
Post login information to receive a JWT
Either:
- email & password as headers
Or:
- user UUID, JWT as headers

### /actions
An action is something that can be executed remotely on the Raspberry Pi. This route returns all the actions available to execute on the Pi.

### /action?urn=
Route for executing actions
