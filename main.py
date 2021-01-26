from csv import reader

from api import get_url_data

with open('data/request1.csv', 'r') as read_obj:
    csv_reader = reader(read_obj)
    for url_to_check in csv_reader:
        print(get_url_data(url_to_check[0]))
