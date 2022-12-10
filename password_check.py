''' Application to check if Password have been Pwned!'''

import requests
import hashlib
import csv

def request_api_data(query_char):

    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code} check the API and retry.')
    return res


def get_password_leak_count(hashes,hash_to_check):
    ''' gets the count of leaks from the API'''

    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    """_check if the password is in the response data
    """

    passwordsha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5char, tail = passwordsha1[:5],passwordsha1[5:]
    response = request_api_data(first5char)
    return get_password_leak_count(response,tail)

def open_csv(filename):

    with open(filename, mode = 'r',newline='') as file:
        
        reader = csv.reader(file, delimiter = ',')
        
        # store the headers in a separate variable,
        headings = next(reader)
        
        # output list to store all rows
        passwords =[]
        for row in reader:
            passwords.append(row[1])
        return passwords

def main(file):
    passwords = open_csv(file)
    for i in passwords:
        count = pwned_api_check(i)
        if count:
           print(f'{i} has been found {count} times...')
        else:
            print(f'{i} has NOT been found.')
    return 'done.'

main('password.csv')
