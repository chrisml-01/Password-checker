import requests  # to have a browser, without actually having a browser
import hashlib
from sys import argv, exit


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error Fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        # check the [list of hash] to the [tail of the hashed password]
        if h == hash_to_check:
            return count  # return how many times the password has been leaked
    return 0


def pwned_api_check(password):
    # check if password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf=8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    res = request_api_data(first5_char)
    return get_password_leaks_count(res, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... You should probably change your password')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done'


if __name__ == "__main__":
    exit(main(argv[1:]))

# to make it more secure have it read from a text file rather than the command prompt/ terminal
