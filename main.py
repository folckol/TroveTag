from trove import Trove



def get_list(file_name):
    list = []
    with open(file_name) as file:
        while (line := file.readline().rstrip()):
            list.append(line)
    return list


if __name__ == '__main__':
    addresses = get_list('account_files/addresses.txt')
    private_keys = get_list('account_files/private_keys.txt')
    proxies = get_list('account_files/proxy.txt')
    tw_data = get_list('account_files/Twitters.txt')
    discord_tokens = get_list('account_files/discord_tokens.txt')
    mails = get_list('account_files/mails.txt')
    tags = get_list('account_files/tags.txt')

    cap_key = get_list('account_files/CapKey.txt')[0]


    # print([cap_key])
    # input()

    if len(addresses) != len(private_keys) != len(proxies) != len(tw_data) != len(discord_tokens):
        print('Количество элементов в текстовиках не совпадает')
        input()
        exit(1)

    if len(cap_key) < 5:
        print('Вы не указали api ключ от CapMonster')
        input()
        exit(1)

    print('Абуз начался\n\n')

    for i in range(len(addresses)):
        proxy_list = proxies[i].split(':')
        proxy = f'http://{proxy_list[2]}:{proxy_list[3]}@{proxy_list[0]}:{proxy_list[1]}'
        accs_data = {
            'address': addresses[i],
            'private_key': private_keys[i],
            'tw_auth_token': tw_data[i].split('auth_token=')[-1].split(';')[0],
            'tw_csrf': tw_data[i].split('ct0=')[-1].split(';')[0],
            'discord_token': discord_tokens[i],
            'proxy': proxy
        }
        result = Trove(accs_data, cap_key, i).execute_task()
        print(i, '-', result, '\n')
        # trove.get_last_mail(accs_data['mail'].split(':')[0],accs_data['mail'].split(':')[1])
    input()

