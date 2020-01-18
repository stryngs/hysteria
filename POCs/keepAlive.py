import requests
import sys
import time

def newSession():
    headers = {"connection" : "keep-alive",
               "keep-alive" : "timeout=10, max=1000"}

    s = requests.Session()
    s.headers.update(headers)
    return s

if __name__ == '__main__':
    if sys.argv[1] is not None:
        print('Starting in 10 seconds')
        time.sleep(10)
        url = '{0}'.format(sys.argv[1])
        s = newSession()
        while True:
            s.get(url)
            time.sleep(int(sys.argv[2]))
