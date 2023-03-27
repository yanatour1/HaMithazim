import socket
import string
import itertools

HOST = "52.26.191.139"
PORT = 8081

msg = """
            HELLO FIELD AGENT!
            COMMANDS:
                SEND-SECRET-DATA
                GET-SECRET-DATA
                GOODBYE
            """

ABC = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", 'R', "S", "T", "U", "V",
       "W",
       "X", "Y", "Z"]

state = 0
encrypted_chars_read_from_server = -1
encrypted_chars_sent_to_server = -1
queue = []
to_enc = {}
to_dec = {}


def only_letters(message):
    return [letters for letters in message if letters in ABC]


def _get_next_char():
    """
    Gets the next char of the enigma machine
    :return:
    """
    global queue
    global encrypted_chars_read_from_machine

    if len(queue) == 0:
        output = ""
        if encrypted_chars_read_from_machine > 0:
            machine.send(b"\n")
            output = machine.recv(1024).decode("ascii")

            s_clean = "I don't understand you"
            index = output.find(s_clean)
            if index != -1:
                index += len(s_clean)
                output = output[index:]

        if output == "":
            output = machine.recv(1024).decode("ascii")

        s_clean = " \n"
        index = output.find(s_clean)
        if index != -1:
            index += len(s_clean)
            output = output[:index]

        clean_output = only_letters(output)
        assert (len(clean_output) == len(clean_interface_plaintext))
        encrypted_chars_read_from_machine += len(clean_output)
        queue += list(clean_output)

    return queue.pop(0)


def _crack_code():
    combinations = set()
    for i in itertools.count():
        current_char_offset = i % len(clean_interface_plaintext)
        current_machine_state = i % len(ABC)
        state_offset_combination = (current_machine_state, current_char_offset)
        if state_offset_combination in combinations:
            break

        plain_char = clean_interface_plaintext[current_char_offset]
        cipher_char = _get_next_char()
        to_enc[current_machine_state][plain_char] = cipher_char
        to_dec[current_machine_state][cipher_char] = plain_char
        combinations.add(state_offset_combination)


def machine_state():
    return (encrypted_chars_read_from_machine + encrypted_chars_sent_to_machine) % len(ABC)


def send_encrypted_message(plaintext_message):
    """
    The function takes the plain text message, encrypts that and sends to the server
    """
    global encrypted_chars_sent_to_machine

    enc_msg = ""
    enc_nums = 0
    init_st = machine_state()
    for c in plaintext_message:
        if c in ABC:
            enc_msg += to_enc[(init_st + enc_nums) % len(ABC)][c]
            enc_nums += 1
        else:
            enc_msg += c
    machine.send(enc_msg.encode("ascii"))
    encrypted_chars_sent_to_machine += enc_nums
    result = machine.recv(1024).decode("ascii")
    return result[:-1]


def decrypt_message(encrypted_message):
    """
    The function takes the encrypted message and decrypt that
    :return: Decrypted message
    """
    decrypted_message = ""
    num_decrypted_chars = 0
    for c in encrypted_message:
        if c in ABC:
            decrypted_message += to_dec[(machine_state() + num_decrypted_chars) % len(ABC)].get(c, '?')
            num_decrypted_chars += 1
        else:
            decrypted_message += c

    return decrypted_message


r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
r.connect((HOST, PORT))

machine = r
ABC = string.ascii_uppercase
clean_interface_plaintext = only_letters(msg)
state = 0
encrypted_chars_read_from_machine = 0
encrypted_chars_sent_to_machine = 0
queue = []
to_enc = [dict() for i in range(len(ABC))]
to_dec = [dict() for i in range(len(ABC))]
machine.recv(1024)
_crack_code()

flag = send_encrypted_message("GET-SECRET-DATA")
print(decrypt_message(flag))  # The final answer to HaMithazim CTF
