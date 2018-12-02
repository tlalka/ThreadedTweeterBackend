def load_test_data(example_number):
    msgs = pickle.load(open(f'{path}/list_of_msgs_{market}', 'rb'))
    starting_book = pickle.load(open(f'{path}/starting_orderbook_{market}', 'rb'))
    expected_book = pickle.load(open(f'{path}/expected_orderbook_{market}', 'rb'))
    return msgs, starting_book, expected_book