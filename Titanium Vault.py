import base64
import random
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import os
from passlib.hash import pbkdf2_sha256
import tkinter as tk
from tkinter import *
from tkinter import messagebox, ttk
from PIL import ImageTk, Image
from datetime import date
import webbrowser
import pickle
import winreg


root = Tk()
root.state('zoomed')
root.title("Titanium Vault - Password Manager")
root.iconbitmap("resources/Media/Icon/Titanium_Vault_Icon.ico")
w, h = root.winfo_screenwidth(), root.winfo_screenheight()
# print(w, h)
root.geometry("%dx%d+0+0" % (w, h))
root.configure(bg="#2b2b2b")

logged_in = False
passwords_key = ""


def pad(s):
    block_size = 16
    remainder = len(s) % block_size
    padding_needed = block_size - remainder
    return s + padding_needed * ' '


def unpad(s):
    return s.rstrip()


def encrypt(plain_text, password):
    # generate a random salt
    salt = os.urandom(AES.block_size)

    # generate a random iv
    iv = Random.new().read(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # pad text with spaces to be valid for AES CBC mode
    padded_text = pad(plain_text)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_CBC, iv)

    # return a dictionary with the encrypted text
    return {
        'cipher_text': base64.b64encode(cipher_config.encrypt(padded_text.encode("utf8"))),
        'salt': base64.b64encode(salt),
        'iv': base64.b64encode(iv)
    }


def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = base64.b64decode(enc_dict['salt'])
    enc = base64.b64decode(enc_dict['cipher_text'])
    iv = base64.b64decode(enc_dict['iv'])

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_CBC, iv)

    # decrypt the cipher text
    decrypted = cipher.decrypt(enc)

    # unpad the text to remove the added spaces
    original = unpad(decrypted)

    return original


REG_PATH = r"SOFTWARE\Titanium Vault"


def set_reg(name, value):
    try:
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0,
                                      winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, name, 0, winreg.REG_SZ, value)
        winreg.CloseKey(registry_key)
        return True
    except WindowsError:
        return False


def get_reg(name):
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0,
                                      winreg.KEY_READ)
        value, regtype = winreg.QueryValueEx(registry_key, name)
        winreg.CloseKey(registry_key)
        return value
    except WindowsError:
        return None


def rescale_x(pixels):
    root.update()
    return int(pixels * (root.winfo_screenwidth() / 1280))


def rescale_y(pixels):
    root.update()
    return int(pixels * (root.winfo_screenheight() / 720))


def rescale_font(size):
    root.update()
    return int(min(rescale_x(size), rescale_y(size)))


def set_username_page():
    username_frame = LabelFrame(root, bg="#2b2b2b", padx=rescale_x(5), pady=rescale_y(5), relief=RAISED)
    username_frame.place(relx=0.5, rely=0.45, anchor='n')
    username_frame.grid_columnconfigure(0, minsize=rescale_x(100))
    username_frame.grid_columnconfigure(4, minsize=rescale_x(100))
    username_frame.grid_rowconfigure(1,  minsize=rescale_y(80))
    username_frame.grid_rowconfigure(5,  minsize=rescale_y(40))

    welcome_label = Label(username_frame, text="Welcome!", bg="#2b2b2b", fg="#FEB868",
                          font="Monosten " + str(rescale_font(24)), justify=CENTER)
    welcome_label.grid(row=0, column=1, columnspan=3, pady=rescale_y(10))

    enter_username_label = Label(username_frame, text="Enter username:", bg="#2b2b2b", fg="#FEB868",
                                 font="Monosten " + str(rescale_font(14)))
    enter_username_label.grid(row=2, column=1, pady=rescale_y(10), sticky="w")

    input_field = Entry(username_frame, width=rescale_font(40), font=("arial", rescale_font(12)), justify=CENTER,
                        bg="#5B666D", fg="white", relief=RIDGE, borderwidth=5)
    input_field.grid(row=3, column=1, columnspan=3)

    def received_input_username(x=""):
        username = str(input_field.get()).strip()
        if username != "":
            file = open("cfg/profile/account_info.txt", "a")
            start_date = str(date.today())
            start_date = start_date[-2:] + start_date[-6:-2] + start_date[:-6]
            file.write(username + "\n" + start_date + "\n")
            file.close()
            username_frame.place_forget()
            root.unbind('<Return>')
            set_master_password_page(username)

    pickle_in = open("cfg/saves/app_encrypt.pickle", "wb")
    pickle.dump({}, pickle_in)
    pickle_in.close()

    visits_pickle_out = open("resources/data/visits.pickle", "wb")
    pickle.dump({}, visits_pickle_out)
    visits_pickle_out.close()

    next_button = Button(username_frame, text="Next", bg="#36d5b5", fg="Black", command=received_input_username,
                         padx=rescale_x(20), pady=rescale_y(6), font="calibri " + str(rescale_font(10)), cursor="hand2")
    next_button.grid(row=4, column=3, pady=rescale_y(5), sticky="e")

    root.bind('<Return>', received_input_username)


def set_master_password_page(username):
    global logged_in, passwords_key
    set_master_password_frame = LabelFrame(root, bg="#2b2b2b", padx=rescale_x(5), pady=rescale_y(5), relief=RAISED)
    set_master_password_frame.place(relx=0.5, rely=0.45, anchor='n')
    set_master_password_frame.grid_columnconfigure(0, minsize=rescale_x(100))
    set_master_password_frame.grid_columnconfigure(4, minsize=rescale_x(100))
    set_master_password_frame.grid_rowconfigure(1, minsize=rescale_y(60))
    set_master_password_frame.grid_rowconfigure(4, minsize=rescale_y(20))
    set_master_password_frame.grid_rowconfigure(8, minsize=rescale_y(20))

    greeting_label = Label(set_master_password_frame, text="Hi " + username + "!", bg="#2b2b2b", fg="#FEB868",
                           font="Monosten " + str(rescale_font(24)), justify=CENTER)
    greeting_label.grid(row=0, column=1, columnspan=3)

    set_password_label = Label(set_master_password_frame, text="Set your master password:",  bg="#2b2b2b", fg="#FEB868",
                               font="Monosten " + str(rescale_font(14)))
    set_password_label.grid(row=2, column=1, columnspan=2, sticky="w")

    enter_password_field = Entry(set_master_password_frame, width=rescale_font(40), font=("arial", rescale_font(12)),
                                 show="•", justify=CENTER, bg="#5B666D", fg="white", relief=RIDGE, borderwidth=5)
    enter_password_field.grid(row=3, column=1, columnspan=3)

    def check_match(x=""):
        global passwords_key
        if confirm_password_field.get().strip() != "":
            input_pass = str(enter_password_field.get())
            hash = pbkdf2_sha256.hash(input_pass)
            set_reg('Master_Hash', str(hash))
            if pbkdf2_sha256.verify(confirm_password_field.get(), hash):
                passwords_key = str(generate_random_password() + generate_random_password())
                set_reg('Enc_Pass_Key', str(encrypt(passwords_key, input_pass)))
                set_master_password_frame.place_forget()
                root.unbind('<Return>')
                login_page.header.place_forget()
                login_page.logo_label.place_forget()
                main_layout()
                add_website_page()
            else:
                invalid_match_label = Label(set_master_password_frame, text="Passwords do not match. Please try again.",
                                            fg="red", bg="#2b2b2b", font="calibri " + str(rescale_font(10)))
                invalid_match_label.grid(row=9, column=1, columnspan=3)

    confirm_password_label = Label(set_master_password_frame, text="Confirm password:", justify=LEFT, bg="#2b2b2b",
                                   fg="#FEB868", font="Monosten " + str(rescale_font(14)))
    confirm_password_label.grid(row=5, column=1, columnspan=2, sticky="w")

    confirm_password_field = Entry(set_master_password_frame, width=rescale_font(40), font=("arial", rescale_font(12)),
                                   show="•", justify=CENTER, bg="#5B666D", fg="white", relief=RIDGE, borderwidth=5)
    confirm_password_field.grid(row=6, column=1, columnspan=3)

    set_password_button = Button(set_master_password_frame, text="Set password", justify=CENTER, fg="Black",
                                 bg="#36d5b5", command=check_match, padx=rescale_x(20), pady=rescale_y(6),
                                 font="calibri " + str(rescale_font(10)), cursor="hand2")
    set_password_button.grid(row=7, column=3, sticky="e", pady=rescale_y(5))

    root.bind('<Return>', check_match)


def login_page():
    global logo, logged_in, passwords_key
    login_page.header = Label(root, text="Titanium Vault", justify=CENTER, bg="#2b2b2b", fg="#36d5b5",
                              font="Monosten " + str(rescale_font(40)))
    login_page.header.place(relx=0.5, rely=0, anchor='n')

    logo_image = Image.open("resources/Media/Icon/Titanium_Vault_Logo.jpg")
    logo_image = logo_image.resize((rescale_font(200), rescale_font(200)), Image.ANTIALIAS)
    logo = ImageTk.PhotoImage(logo_image)

    login_page.logo_label = Label(root, image=logo, pady=rescale_y(5))
    login_page.logo_label.place(relx=0.5, rely=0.1, anchor='n')

    file = open("cfg/profile/account_info.txt", "r")
    info = file.readlines()
    if not info:
        set_username_page()
        file.close()
    else:
        username = str(info[0]).strip("\n")
        # print(username)
        file.close()

        login_page_frame = LabelFrame(root, bg="#2b2b2b", padx=rescale_x(5), pady=rescale_y(5), relief=RAISED)
        login_page_frame.place(relx=0.5, rely=0.45, anchor='n')
        login_page_frame.grid_columnconfigure(0, minsize=rescale_x(100))
        login_page_frame.grid_columnconfigure(4, minsize=rescale_x(100))
        login_page_frame.grid_rowconfigure(1,  minsize=rescale_y(80))
        login_page_frame.grid_rowconfigure(5,  minsize=rescale_y(40))

        greeting_label = Label(login_page_frame, text="Welcome " + username + "!", bg="#2b2b2b", fg="#FEB868",
                               font="Monosten " + str(rescale_font(24)), justify=CENTER)
        greeting_label.grid(row=0, column=1, columnspan=3)

        enter_master_password_label = Label(login_page_frame, text="Enter Master Password:",  bg="#2b2b2b",
                                            fg="#FEB868", font="Monosten " + str(rescale_font(14)))
        enter_master_password_label.grid(row=2, column=1, columnspan=2, sticky="w")

        enter_master_password_field = Entry(login_page_frame, width=rescale_font(40), font=("arial", rescale_font(12)),
                                            show="•", justify=CENTER, bg="#5B666D", fg="white", relief=RIDGE,
                                            borderwidth=5)
        enter_master_password_field.grid(row=3, column=1, columnspan=3)

        def verify_password(x=""):
            global passwords_key
            hash = get_reg('Master_Hash')
            input_pass = enter_master_password_field.get()
            if pbkdf2_sha256.verify(input_pass, hash):
                passwords_key = bytes.decode(decrypt(eval(get_reg("Enc_Pass_Key")), input_pass))
                login_page_frame.place_forget()
                root.unbind('<Return>')
                login_page.header.place_forget()
                login_page.logo_label.place_forget()
                main_layout()
                home_page()
                # logged_in = True
            else:
                try:
                    verify_password.invalid_match_label.grid_forget()
                except:
                    pass
                verify_password.invalid_match_label = Label(login_page_frame, text="Wrong password!! Try again.",
                                                            fg="red", bg="#2b2b2b",
                                                            font="calibri " + str(rescale_font(10)))
                verify_password.invalid_match_label.grid(row=6, column=1, columnspan=3)

        next_button = Button(login_page_frame, text="Next", justify=CENTER, fg="Black",
                             bg="#36d5b5", command=verify_password, padx=rescale_x(20), pady=rescale_y(6),
                             font="calibri " + str(rescale_font(10)), cursor="hand2")
        next_button.grid(row=4, column=3, sticky="e", pady=rescale_y(5))

        root.bind('<Return>', verify_password)


def main_layout():
    global quit_button, logo, add_website_logo, get_password_logo, update_password_logo, w, h, quit_button_img
    global profile_icon, about_logo

    destroy_frames()
    header_frame = LabelFrame(root, padx=rescale_x(5), pady=rescale_y(5), bg="#36d5b5")
    header_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
    root.grid_columnconfigure(1, weight=1)
    header_frame.grid_columnconfigure(1, weight=1)
    header_frame.grid_columnconfigure(3, weight=1)
    # header_frame.grid_columnconfigure(1, minsize=0.3*w)
    # header_frame.grid_columnconfigure(3, minsize=0.3*w)

    logo_image = Image.open("resources/Media/Icon/Titanium_Vault_Logo.jpg")
    logo_image = logo_image.resize((rescale_font(50), rescale_font(50)), Image.ANTIALIAS)
    logo = ImageTk.PhotoImage(logo_image)

    home_button = Button(header_frame, image=logo, bg="#36d5b5", command=home_page, cursor="hand2")
    home_button.grid(row=0, column=0)
    # home_button.place(relx=0, rely=0)

    title_label = Label(header_frame, text="Titanium Vault", fg="#2b2b2b", bg="#36d5b5", justify=CENTER,
                        font="Monosten " + str(rescale_font(32)))
    title_label.grid(row=0, column=2)

    profile_frame = LabelFrame(header_frame, bg="#36d5b5")
    profile_frame.grid(row=0, column=4)

    profile_icon_image = Image.open("resources/Media/Images/profile_icon_button.png")
    profile_icon_image = profile_icon_image.resize((rescale_font(30), rescale_font(30)), Image.ANTIALIAS)
    profile_icon = ImageTk.PhotoImage(profile_icon_image)

    profile_icon_button = Button(profile_frame, image=profile_icon, bg="#36d5b5", command=profile_page, cursor="hand2")
    profile_icon_button.grid(row=0, column=0, sticky="e")

    file = open("cfg/profile/account_info.txt", "r")
    username = str(file.readlines()[0]).strip("\n")
    file.close()
    username_button = Button(profile_frame, text=username, fg="#2b2b2b", bg="#36d5b5",
                             font="Monosten " + str(rescale_font(10)), command=profile_page, cursor="hand2")
    username_button.grid(row=0, column=1, sticky="ns")

    navigation_pane_frame = LabelFrame(root, padx=rescale_x(10), pady=rescale_y(5), bg="#413F4F", relief=FLAT)
    navigation_pane_frame.grid(row=1, column=0, rowspan=2, sticky="ns")

    root.grid_rowconfigure(1, weight=1)
    navigation_pane_frame.grid_rowconfigure(0, weight=1)
    navigation_pane_frame.grid_rowconfigure(2, weight=1)
    navigation_pane_frame.grid_rowconfigure(4, weight=1)
    navigation_pane_frame.grid_rowconfigure(6, weight=1)
    navigation_pane_frame.grid_rowconfigure(8, weight=1)

    add_website_logo = Image.open("resources/Media/Images/add_new_button.png")
    add_website_logo = add_website_logo.resize((rescale_font(50), rescale_font(50)), Image.ANTIALIAS)
    add_website_logo = ImageTk.PhotoImage(add_website_logo)

    add_website_button = Button(navigation_pane_frame, image=add_website_logo, bg="#CCC9DD", cursor="hand2",
                                command=add_website_page, relief=RAISED)
    add_website_button.grid(row=1, column=0, sticky="n")

    get_password_logo = Image.open("resources/Media/Images/view_password_button.png")
    get_password_logo = get_password_logo.resize((rescale_font(50), rescale_font(50)), Image.ANTIALIAS)
    get_password_logo = ImageTk.PhotoImage(get_password_logo)

    get_password_button = Button(navigation_pane_frame, image=get_password_logo, bg="#CCC9DD", cursor="hand2",
                                 command=get_password_page, relief=RAISED)
    get_password_button.grid(row=3, column=0)

    about_logo = Image.open("resources/Media/Images/about_button.png")
    about_logo = about_logo.resize((rescale_font(50), rescale_font(50)), Image.ANTIALIAS)
    about_logo = ImageTk.PhotoImage(about_logo)

    about_logo_button = Button(navigation_pane_frame, image=about_logo, bg="#CCC9DD", cursor="hand2", relief=RAISED,
                               command=about_page)
    about_logo_button.grid(row=5, column=0)

    def quit_application():
        quit = messagebox.askyesno("Titanium Vault", "Are you sure you want to exit?")

        if quit:
            root.quit()

    quit_button_img = Image.open("resources/Media/Images/quit_button_transparent.png")
    quit_button_img = quit_button_img.resize((rescale_font(50), rescale_font(50)), Image.ANTIALIAS)
    quit_button_img = ImageTk.PhotoImage(quit_button_img)

    quit_button = Button(navigation_pane_frame, image=quit_button_img, bg="#CCC9DD", command=quit_application,
                         cursor="hand2")
    quit_button.grid(row=7, column=0, sticky="e")

    root.update()
    # print(navigation_pane_frame.winfo_width(), navigation_pane_frame.winfo_height())


def profile_page():
    global edit_icon_image
    destroy_frames()
    profile_page.profile_frame = LabelFrame(root, text="Profile", padx=rescale_x(5), pady=rescale_y(5),
                                            font="calibri " + str(rescale_font(12)), bg="#2b2b2b", fg="white")
    profile_page.profile_frame.grid(row=1, column=1, padx=rescale_x(5), pady=rescale_y(5), sticky="nsew")
    profile_page.profile_frame.grid_columnconfigure(0, weight=1)
    profile_page.profile_frame.grid_columnconfigure(3, weight=1)
    profile_page.profile_frame.grid_rowconfigure(1, weight=1)
    profile_page.profile_frame.grid_rowconfigure(7, weight=1)

    header_label = Label(profile_page.profile_frame, text="User Info", bg="#2b2b2b", fg="#009BA3",
                         font="calibri " + str(rescale_font(30)), justify=CENTER)
    header_label.grid(row=0, column=1)

    username_title_label = Label(profile_page.profile_frame, text="Username:", bg="#2b2b2b", fg="#FEB868",
                                 font="Monosten " + str(rescale_font(16)))
    username_title_label.grid(row=2, column=1, sticky="w")

    file = open("cfg/profile/account_info.txt", "r")
    info_list = file.readlines()
    username = str(info_list[0]).strip("\n")
    start_date = str(info_list[1]).strip("\n")
    file.close()

    profile_page.username_label = Label(profile_page.profile_frame, text=username, bg="#2b2b2b", fg="#36d5b5",
                                        font="Monosten " + str(rescale_font(15)))
    profile_page.username_label.grid(row=3, column=1)

    def save_username(new_username):
        if new_username != "":
            file = open("cfg/profile/account_info.txt", "w")
            file.write(new_username + "\n" + start_date + "\n")
            file.close()

            messagebox.showinfo("Titanium Vault", "Username updated successfully!")
            main_layout()
            profile_page()

    def edit_username(old_username):
        global confirm_change_icon_image
        profile_page.username_label.grid_forget()
        edit_username_button.grid_forget()

        edit_username_field = Entry(profile_page.profile_frame, width=rescale_font(40), bg="#5B666D", fg="white",
                                    font=("arial", rescale_font(12)), justify=CENTER, relief=RIDGE, borderwidth=5)
        edit_username_field.grid(row=3, column=1)
        edit_username_field.insert(0, old_username)

        confirm_change_icon_image = Image.open("resources/Media/Images/confirm_button.png")
        confirm_change_icon_image = confirm_change_icon_image.resize((rescale_font(20), rescale_font(20)),
                                                                     Image.ANTIALIAS)
        confirm_change_icon_image = ImageTk.PhotoImage(confirm_change_icon_image)

        confirm_change_button = Button(profile_page.profile_frame, image=confirm_change_icon_image, bg="#CCC9DD",
                                       command=lambda: save_username(str(edit_username_field.get()).strip()))
        confirm_change_button.grid(row=3, column=2, sticky="w", padx=rescale_x(10))

    edit_icon_image = Image.open("resources/Media/Images/edit_button.png")
    edit_icon_image = edit_icon_image.resize((rescale_font(20), rescale_font(20)), Image.ANTIALIAS)
    edit_icon_image = ImageTk.PhotoImage(edit_icon_image)

    edit_username_button = Button(profile_page.profile_frame, image=edit_icon_image, bg="#CCC9DD",
                                  command=lambda: edit_username(username))
    edit_username_button.grid(row=3, column=2, sticky="w", padx=rescale_x(10))

    change_master_password_label = Label(profile_page.profile_frame, text="Update Master Password", bg="#2b2b2b",
                                         fg="#FEB868", font="Monosten " + str(rescale_font(15)))
    change_master_password_label.grid(row=4, column=1, pady=rescale_y(20))

    edit_master_password_button = Button(profile_page.profile_frame, image=edit_icon_image, bg="#CCC9DD",
                                         command=update_master_password_page)
    edit_master_password_button.grid(row=4, column=2, sticky="w", padx=rescale_x(10))

    pickle_in = open("cfg/saves/app_encrypt.pickle", "rb")
    pickle_dict = pickle.load(pickle_in)

    saved_passwords_label = Label(profile_page.profile_frame, text="Total Saved Passwords: " + str(len(pickle_dict)),
                                  bg="#2b2b2b", fg="#FEB868", font="Monosten " + str(rescale_font(12)), justify=LEFT)
    saved_passwords_label.grid(row=5, column=1, columnspan=2, sticky="w")

    using_since_label = Label(profile_page.profile_frame, text="Using since: " + start_date, bg="#2b2b2b", fg="#FEB868",
                            font="Monosten " + str(rescale_font(12)), justify=LEFT)
    using_since_label.grid(row=6, column=1, columnspan=2, sticky="w")


def update_master_password_page():
    global passwords_key
    destroy_frames()
    update_master_password_page.update_master_password_frame = LabelFrame(root, padx=rescale_x(5), pady=rescale_y(5),
                                                                          bg="#2b2b2b")
    update_master_password_page.update_master_password_frame.grid(row=1, column=1, padx=rescale_x(5), pady=rescale_y(5),
                                                                  sticky="nsew")
    update_master_password_page.update_master_password_frame.grid_columnconfigure(0, weight=1)
    update_master_password_page.update_master_password_frame.grid_columnconfigure(3, weight=1)
    update_master_password_page.update_master_password_frame.grid_rowconfigure(1, weight=1)
    update_master_password_page.update_master_password_frame.grid_rowconfigure(9, weight=1)

    update_master_password_label = Label(update_master_password_page.update_master_password_frame,
                                         text="Update Master Password", fg="#009BA3", bg="#2b2b2b",
                                         font="Monosten " + str(rescale_font(20)), justify=CENTER)
    update_master_password_label.grid(row=0, column=1, columnspan=2)

    current_master_password_label = Label(update_master_password_page.update_master_password_frame,
                                          text="Enter current master password", fg="#FEB868", bg="#2b2b2b",
                                         font="Monosten " + str(rescale_font(12)), justify=LEFT)
    current_master_password_label.grid(row=2, column=1, sticky="w", pady=(rescale_y(15), rescale_y(2)))

    current_master_password_field = Entry(update_master_password_page.update_master_password_frame, bg="#5B666D",
                                          fg="white", font=("arial", rescale_font(12)), justify=CENTER, relief=RIDGE,
                                          borderwidth=5, show="•")
    current_master_password_field.grid(row=3, column=1, columnspan=2, sticky="ew")

    new_master_password_label = Label(update_master_password_page.update_master_password_frame,
                                      text="Enter new master password", fg="#FEB868", bg="#2b2b2b",
                                      font="Monosten " + str(rescale_font(12)), justify=LEFT)
    new_master_password_label.grid(row=4, column=1, sticky="w", pady=(rescale_y(15), rescale_y(2)))

    new_master_password_field = Entry(update_master_password_page.update_master_password_frame, bg="#5B666D", show="•",
                                      fg="white", font=("arial", rescale_font(12)), justify=CENTER, relief=RIDGE,
                                      borderwidth=5)
    new_master_password_field.grid(row=5, column=1, columnspan=2, sticky="ew")

    def use_suggested_password(sug_pass):
        copy_to_clipboard(sug_pass)
        new_master_password_field.delete(0, END)
        new_master_password_field.insert(0, sug_pass)
        confirm_new_master_password_field.delete(0, END)
        confirm_new_master_password_field.insert(0, sug_pass)

    suggested_password = generate_random_password()
    suggested_password_label = Button(update_master_password_page.update_master_password_frame,
                                      text="Suggested Password:-\n" + suggested_password, fg="#FF3300", bg="#F2ECFF",
                                      command=lambda: use_suggested_password(suggested_password), cursor="hand2",
                                      font="calibri " + str(rescale_font(11)), padx=rescale_x(20))
    suggested_password_label.grid(row=4, rowspan=2, column=3, padx=rescale_x(20), sticky="sw")

    confirm_new_master_password_label = Label(update_master_password_page.update_master_password_frame,
                                              text="Confirm new master password", fg="#FEB868", bg="#2b2b2b",
                                              font="Monosten " + str(rescale_font(12)), justify=LEFT)
    confirm_new_master_password_label.grid(row=6, column=1, sticky="w", pady=(rescale_y(15), rescale_y(2)))

    confirm_new_master_password_field = Entry(update_master_password_page.update_master_password_frame, bg="#5B666D",
                                              fg="white", font=("arial", rescale_font(12)), justify=CENTER,
                                              relief=RIDGE, borderwidth=5, show="•")
    confirm_new_master_password_field.grid(row=7, column=1, columnspan=2, sticky="ew")

    def verify_old_password():
        try:
            verify_old_password.invalid_master_password.grid_forget()
        except:
            pass
        hash = get_reg('Master_Hash')
        if pbkdf2_sha256.verify(current_master_password_field.get(), hash):
            return True
        else:
            verify_old_password.invalid_master_password = Label(update_master_password_page.update_master_password_frame,
                                            text="Wrong password!! Try again.", fg="red", bg="#2b2b2b",
                                            font="calibri " + str(rescale_font(10)))
            verify_old_password.invalid_master_password.grid(row=3, column=3, sticky="w")
            return False

    def update_master_password():
        global passwords_key
        if not verify_old_password():
            return
        if confirm_new_master_password_field.get().strip() != "":
            input_pass = str(new_master_password_field.get())
            hash = pbkdf2_sha256.hash(input_pass)
            if pbkdf2_sha256.verify(confirm_new_master_password_field.get(), hash):
                set_reg('Master_Hash', str(hash))
                set_reg('Enc_Pass_Key', str(encrypt(passwords_key, input_pass)))
                messagebox.showinfo("Titanium Vault", "Master Password updated successfully!!")
                profile_page()
            else:
                try:
                    update_master_password.invalid_match_label.grid_forget()
                except:
                    pass

                update_master_password.invalid_match_label = Label(
                    update_master_password_page.update_master_password_frame,
                    text="Passwords do not match. Please try again.",
                    fg="red", bg="#2b2b2b",
                    font="calibri " + str(rescale_font(10))
                                                                    )
                update_master_password.invalid_match_label.grid(row=7, column=3, sticky="w")

    update_button = Button(update_master_password_page.update_master_password_frame, text="Update", fg="Black",
                           bg="#36d5b5", padx=rescale_x(5), pady=rescale_y(2), command=update_master_password)
    update_button.grid(row=8, column=2, sticky="e", pady=rescale_y(5))


def home_page():
    destroy_frames()
    home_page.frequently_used_frame = LabelFrame(root, text="Frequently Used", padx=rescale_x(5), pady=rescale_y(5),
                                                 font="calibri " + str(rescale_font(12)), bg="#2b2b2b", fg="White")
    home_page.frequently_used_frame.grid(row=1, column=1, padx=rescale_x(5), pady=rescale_y(2), sticky="nsew")
    home_page.frequently_used_frame.grid_columnconfigure(0, weight=1)
    home_page.frequently_used_frame.grid_columnconfigure(1, weight=1)
    home_page.frequently_used_frame.grid_columnconfigure(2, weight=1)
    home_page.frequently_used_frame.grid_rowconfigure(0, weight=1)
    home_page.frequently_used_frame.grid_rowconfigure(1, weight=1)
    home_page.frequently_used_frame.grid_rowconfigure(2, weight=1)

    visits_pickle_in = open("resources/data/visits.pickle", "rb")
    visits_dict = pickle.load(visits_pickle_in)

    visit_and_website_list = [(visits_dict[key], key) for key in list(visits_dict.keys())]
    visit_and_website_list.sort(reverse=True)

    i = 0
    for t in visit_and_website_list[:9]:
        website_email = t[1].split("~~")
        app_frame = LabelFrame(home_page.frequently_used_frame, text=website_email[0],
                               font="calibri " + str(rescale_font(20)), padx=rescale_x(10), pady=rescale_y(5),
                               bg="#2b2b2b", fg="#FEB868")
        app_frame.grid(row=i // 3, column=i % 3, sticky="nsew", padx=rescale_x(5))
        app_frame.grid_columnconfigure(0, weight=1)
        app_frame.grid_rowconfigure(0, weight=1)
        app_frame.grid_rowconfigure(1, weight=1)

        email_label = Label(app_frame, text=website_email[1], font="calibri " + str(rescale_font(12)), bg="#2b2b2b",
                            fg="#FEB868")
        email_label.grid(row=0, column=0)

        get_password_button = Button(app_frame, text="Copy Password!", bg="#36d5b5", fg="Black",
                                     font="calibri " + str(rescale_font(10)), cursor="hand2",
                                     command=lambda key=t[1]: copy_to_clipboard(get_password(key)))

        get_password_button.grid(row=1, column=0)

        i += 1
    return


def generate_random_password():
    characters = ["~", "`", "!", "@", "#", "$", "%", "^", "&", "*",
                  "-", "_", "=", "+", "/", "?", ";", ":", "0", "1",
                  "2", "3", "4", "5", "6", "7", "8", "9", "a", "b",
                  "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
                  "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
                  "w", "x", "y", "z", "A", "B", "C", "D", "E", "F",
                  "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
                  "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]
    chars_for_pass = []
    for alpha in range(3):
        chars_for_pass.append(random.choice(characters[28:54]))
        chars_for_pass.append(random.choice(characters[0:18]))
        chars_for_pass.append(random.choice(characters[18:28]))
        chars_for_pass.append(random.choice(characters[54:]))
    chars_for_pass += [random.choice(characters) for x in range(8)]
    chars_for_pass = chars_for_pass[1:]
    random.shuffle(chars_for_pass)
    return "".join([random.choice(characters[28:])] + chars_for_pass)


def copy_to_clipboard(text):
    root.clipboard_clear()
    root.clipboard_append(str(text))
    root.update()
    # messagebox.showinfo(title="Titanium Vault", message="Password copied to clipboard")


def save_password(website, email_id, password, come_back_to=""):
    global passwords_key
    try:
        encrypted_pass_pickle_in = open("cfg/saves/app_encrypt.pickle", "rb")
        encrypted_pass_dict = pickle.load(encrypted_pass_pickle_in)

        visits_pickle_in = open("resources/data/visits.pickle", "rb")
        visits_dict = pickle.load(visits_pickle_in)
    except EOFError:
        encrypted_pass_dict = {}
        visits_dict = {}

    key = website + "~~" + email_id

    if key in encrypted_pass_dict and come_back_to != "get_password_page":
        response = messagebox.askyesno("Titanium Vault", "There is already a password stored with the same website \n"
                                                         "and email. Do you want to overwrite that password?")
        if not response:
            return

    visits_dict[key] = 0

    encrypted_pass_dict[key] = encrypt(password, passwords_key)

    encrypted_pass_pickle_out = open("cfg/saves/app_encrypt.pickle", "wb")
    pickle.dump(encrypted_pass_dict, encrypted_pass_pickle_out)
    encrypted_pass_pickle_out.close()

    visits_pickle_out = open("resources/data/visits.pickle", "wb")
    pickle.dump(visits_dict, visits_pickle_out)
    visits_pickle_out.close()

    messagebox.showinfo(title="Titanium Vault", message="Password saved successfully!!!")

    if come_back_to == "get_password_page":
        get_password_page()
    else:
        add_website_page()


def add_website_page():
    destroy_frames()
    add_website_page.add_website_frame = LabelFrame(root, padx=rescale_x(5), pady=rescale_y(5), bg="#2b2b2b")
    add_website_page.add_website_frame.grid(row=1, column=1, padx=rescale_x(5), pady=rescale_y(2), sticky="nsew")
    add_website_page.add_website_frame.grid_rowconfigure(1, weight=1)
    add_website_page.add_website_frame.grid_rowconfigure(4, weight=1)
    add_website_page.add_website_frame.grid_rowconfigure(7, weight=1)
    add_website_page.add_website_frame.grid_rowconfigure(11, weight=1)
    add_website_page.add_website_frame.grid_columnconfigure(0, weight=1)
    # add_website_page.add_website_frame.grid_columnconfigure(1, weight=1)
    add_website_page.add_website_frame.grid_columnconfigure(2, weight=1)

    add_website_label = Label(add_website_page.add_website_frame, text="Save password for a Website or App",
                              fg="#009BA3", bg="#2b2b2b", font="Monosten " + str(rescale_font(20)), justify=CENTER)
    add_website_label.grid(row=0, column=0, columnspan=3, pady=rescale_y(10))

    name_of_website_label = Label(add_website_page.add_website_frame, text="Name of Website/App", bg="#2b2b2b",
                                  font="calibri " + str(rescale_font(12)), fg="#FEB868", justify=CENTER)
    name_of_website_label.grid(row=2, column=1, sticky="w")

    name_of_website_field = Entry(add_website_page.add_website_frame, width=rescale_font(40), justify=CENTER,
                                  font="calibri " + str(rescale_font(10)), fg="white", bg="#5B666D", borderwidth=5)
    name_of_website_field.grid(row=3, column=1)

    email_id_on_website_label = Label(add_website_page.add_website_frame, text="Email-ID on Website/App", bg="#2b2b2b",
                                      font="calibri " + str(rescale_font(12)), fg="#FEB868", justify=CENTER)
    email_id_on_website_label.grid(row=5, column=1, sticky="w")

    email_id_on_website_field = Entry(add_website_page.add_website_frame, width=rescale_font(40), justify=CENTER,
                                      font="calibri " + str(rescale_font(10)), fg="white", bg="#5B666D", borderwidth=5)
    email_id_on_website_field.grid(row=6, column=1)

    password_label = Label(add_website_page.add_website_frame, text="Password", bg="#2b2b2b", fg="#FEB868",
                           font="calibri " + str(rescale_font(12)), justify=CENTER)
    password_label.grid(row=8, column=1, sticky="w")

    password_field = Entry(add_website_page.add_website_frame, width=rescale_font(40), show="•", justify=CENTER,
                           font="calibri " + str(rescale_font(10)), fg="white", bg="#5B666D", borderwidth=5)
    password_field.grid(row=9, column=1)

    def use_suggested_password(sug_pass):
        copy_to_clipboard(sug_pass)
        password_field.delete(0, END)
        password_field.insert(0, sug_pass)

    suggested_password = generate_random_password()
    suggested_password_label = Button(add_website_page.add_website_frame,
                                      text="Suggested Password:-\n" + suggested_password, fg="#FF3300", bg="#F2ECFF",
                                      command=lambda: use_suggested_password(suggested_password), cursor="hand2",
                                      font="calibri " + str(rescale_font(11)), padx=rescale_x(20))
    suggested_password_label.grid(row=8, rowspan=2, column=2, padx=rescale_x(20), sticky="w")

    save_website_button = Button(add_website_page.add_website_frame, text="Save", bg="#36d5b5",
                                 font="calibri " + str(rescale_font(10)), cursor="hand2",
                                 command=lambda: save_password(name_of_website_field.get(),
                                                               email_id_on_website_field.get(), password_field.get()))
    save_website_button.grid(row=10, column=1, sticky="e", pady=rescale_y(10))


def update_password_page(key=None):
    destroy_frames()
    update_password_page.update_password_frame = LabelFrame(root, padx=rescale_x(5), pady=rescale_y(5), bg="#2b2b2b")
    update_password_page.update_password_frame.grid(row=1, column=1, padx=rescale_x(5), pady=rescale_y(2),
                                                    sticky="nsew")
    update_password_page.update_password_frame.grid_columnconfigure(0, weight=1)
    update_password_page.update_password_frame.grid_columnconfigure(4, weight=1)
    update_password_page.update_password_frame.grid_rowconfigure(6, weight=1)

    head_label = Label(update_password_page.update_password_frame, text="Update Password", fg="#009BA3", bg="#2b2b2b",
                       font="Monosten " + str(rescale_font(25)), justify=CENTER)
    head_label.grid(row=0, column=1, columnspan=3, pady=(rescale_y(10), rescale_y(90)))

    website_and_email = key.split("~~")

    website_label = Label(update_password_page.update_password_frame, text=website_and_email[0], fg="#FEB868",
                          bg="#2b2b2b", font="Monosten " + str(rescale_font(20)), justify=CENTER)
    website_label.grid(row=1, column=1, columnspan=3, pady=rescale_y(20))

    email_label = Label(update_password_page.update_password_frame, text=website_and_email[1], fg="#FEB868",
                        bg="#2b2b2b", font="Monosten " + str(rescale_font(15)), justify=CENTER)
    email_label.grid(row=2, column=1, columnspan=3, pady=rescale_y(5))

    updated_password_label = Label(update_password_page.update_password_frame, text="Enter new password:", fg="#FEB868",
                                   bg="#2b2b2b", font=rescale_font(10))

    updated_password_label.grid(row=3, column=2, pady=(rescale_y(40), rescale_y(5)), sticky="w")

    updated_password_field = Entry(update_password_page.update_password_frame, width=rescale_font(40), show="•",
                                   borderwidth=5, fg="white", bg="#5B666D", justify=CENTER)
    updated_password_field.grid(row=4, column=2, padx=rescale_x(5))

    save_button = Button(update_password_page.update_password_frame, text="Save",
                         font="calibri " + str(rescale_font(10)), bg="#36d5b5",
                         command=lambda: save_password(website_and_email[0], website_and_email[1],
                                                       updated_password_field.get(), "get_password_page"))
    save_button.grid(row=5, column=2, pady=rescale_y(5), sticky="e")

    def use_suggested_password(sug_pass):
        copy_to_clipboard(sug_pass)
        updated_password_field.delete(0, END)
        updated_password_field.insert(0, sug_pass)

    suggested_password = generate_random_password()
    suggested_password_label = Button(update_password_page.update_password_frame,
                                      text="Suggested Password:-\n" + suggested_password, fg="#FF3300", bg="#F2ECFF",
                                      command=lambda: use_suggested_password(suggested_password), cursor="hand2",
                                      font="calibri " + str(rescale_font(10)), padx=rescale_x(20))
    suggested_password_label.grid(row=6, rowspan=2, column=2, padx=rescale_x(20), sticky="nw")


def get_password(key):
    global passwords_key
    visits_pickle_in = open("resources/data/visits.pickle", "rb")
    visits_dict = pickle.load(visits_pickle_in)

    visits_dict[key] += 1

    visits_pickle_out = open("resources/data/visits.pickle", "wb")
    pickle.dump(visits_dict, visits_pickle_out)
    visits_pickle_out.close()

    pickle_in = open("cfg/saves/app_encrypt.pickle", "rb")
    pickle_dict = pickle.load(pickle_in)

    passw = decrypt(pickle_dict[key], passwords_key)

    return bytes.decode(passw)


def delete_password(key):
    ask = messagebox.askyesno("Titanium Vault", "Do you want to delete this password?")

    if ask:
        visits_pickle_in = open("resources/data/visits.pickle", "rb")
        visits_dict = pickle.load(visits_pickle_in)

        del visits_dict[key]

        visits_pickle_out = open("resources/data/visits.pickle", "wb")
        pickle.dump(visits_dict, visits_pickle_out)
        visits_pickle_out.close()

        pickle_in = open("cfg/saves/app_encrypt.pickle", "rb")
        pickle_dict = pickle.load(pickle_in)

        del pickle_dict[key]

        pass_pickle_out = open("cfg/saves/app_encrypt.pickle", "wb")
        pickle.dump(pickle_dict, pass_pickle_out)
        pass_pickle_out.close()
    get_password_page()


website_label_font = "calibri " + str(rescale_font(20))
email_label_font = "calibri " + str(rescale_font(12))
get_password_button_font = "calibri " + str(rescale_font(10))

sort_options = [
    "Latest",
    "Oldest",
    "Most used",
    "Least used"
]


def get_password_page(sort_by=sort_options[0]):
    global w, h, website_label_font, email_label_font, get_password_button_font, sort_options
    destroy_frames()
    rescaled_font_10 = str(rescale_font(10))
    get_password_page.get_password_frame = LabelFrame(root, text="Passwords", fg="White", bg="#2b2b2b",
                                                      padx=rescale_x(5), pady=rescale_y(5),
                                                      font="calibri " + str(rescale_font(10)))
    get_password_page.get_password_frame.grid(row=1, column=1, padx=rescale_x(5), pady=rescale_y(2), sticky="nsew")
    # get_password_page.get_password_frame.grid_columnconfigure(0, weight=1)

    my_canvas = Canvas(get_password_page.get_password_frame, bg="#2b2b2b", highlightthickness=0)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)
    # my_canvas.grid_columnconfigure(0, weight=1)

    # Add A Scrollbar To The Canvas
    my_scrollbar = ttk.Scrollbar(get_password_page.get_password_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    # Configure The Canvas
    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

    # Create ANOTHER Frame INSIDE the Canvas
    second_frame = Frame(my_canvas, bg="#2b2b2b")
    second_frame.grid_columnconfigure(0, weight=1)

    # Add that New frame To a Window In The Canvas

    def on_mouse_wheel(event):
        my_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    my_canvas.create_window((0, 0), window=second_frame, anchor="nw")
    my_canvas.bind_all("<MouseWheel>", on_mouse_wheel)

    sort_by_label = Label(second_frame, text="Sort By:", bg="#2b2b2b", fg="White",
                          font="calibri " + rescaled_font_10)

    def use_choice(x=""):
        choice = chosen_option.get()
        if choice == sort_options[0]:
            try:
                pickle_in = open("cfg/saves/app_encrypt.pickle", "rb")
                pickle_dict = pickle.load(pickle_in)
            except EOFError:
                pickle_dict = {}
            show_websites(list(pickle_dict.keys())[::-1])
        elif choice == sort_options[1]:
            try:
                pickle_in = open("cfg/saves/app_encrypt.pickle", "rb")
                pickle_dict = pickle.load(pickle_in)
            except EOFError:
                pickle_dict = {}
            show_websites(list(pickle_dict.keys()))
        elif choice == sort_options[2]:
            try:
                visits_pickle_in = open("resources/data/visits.pickle", "rb")
                visits_dict = pickle.load(visits_pickle_in)

                visit_and_website_list = [(visits_dict[key], key) for key in list(visits_dict.keys())]
            except:
                visit_and_website_list = []

            visit_and_website_list.sort(reverse=True)
            show_websites([x[1] for x in visit_and_website_list])
        elif choice == sort_options[3]:
            try:
                visits_pickle_in = open("resources/data/visits.pickle", "rb")
                visits_dict = pickle.load(visits_pickle_in)

                visit_and_website_list = [(visits_dict[key], key) for key in list(visits_dict.keys())]
            except:
                visit_and_website_list = []

            visit_and_website_list.sort()
            show_websites([x[1] for x in visit_and_website_list])
        else:
            show_websites([])

    chosen_option = StringVar()
    chosen_option.set(sort_by)

    sort_options_dropdown = OptionMenu(second_frame, chosen_option, *sort_options,
                                       command=lambda choice=chosen_option: get_password_page(sort_by=str(choice)))
    sort_options_dropdown.config(bg="#2b2b2b", fg="white", activebackground="#45474B", activeforeground="white",
                                 highlightthickness=0, font="calibri " + rescaled_font_10)
    sort_options_dropdown["menu"].config(bg="#2b2b2b", fg="white", font="calibri " + rescaled_font_10)
    sort_options_dropdown.grid(row=0, column=2, sticky="w", padx=2)


    def show_websites(sorted_websites_list):
        websitesLength = [len(key.split("~~")[0]) for key in sorted_websites_list]
        emailsLength = [len(key.split("~~")[1]) for key in sorted_websites_list]

        maxWebsiteLength = max(websitesLength)
        maxEmailLength = max(emailsLength)

        extraPadding = 0

        if maxWebsiteLength < 17 and maxEmailLength < 35:
            extraPadding += min((17 - maxWebsiteLength) * (250 / 17), (35 - maxEmailLength) * (300 / 35))

        i = 1
        for key in sorted_websites_list:
            website_and_email = key.split("~~")

            website_label = Label(second_frame, text=website_and_email[0], bg="#2b2b2b", fg="#FEB868",
                                  font=website_label_font, wraplength=(250 * w / 1280), justify=CENTER)
            website_label.grid(row=i, column=0, sticky="s")

            email_label = Label(second_frame, text=website_and_email[1], bg="#2b2b2b", fg="#FEB868",
                                font=email_label_font, wraplength=(300 * w / 1280), justify=CENTER)
            email_label.grid(row=i + 1, column=0, sticky="n")

            get_password_button = Button(second_frame, text="Copy Password!", bg="#36d5b5", fg="Black",
                                         font=get_password_button_font, cursor="hand2", pady=4 * (h / 720),
                                         command=lambda key=key: copy_to_clipboard(get_password(key)))
            get_password_button.grid(row=i, column=1, columnspan=2, sticky="sew", padx=((625 + extraPadding) * (w / 1280), 5 * (w / 1280)),
                                     pady=(40 * (h / 720), 2 * (h / 720)))

            update_password_button = Button(second_frame, text="Update Password", bg="#36d5b5", fg="Black",
                                            font=get_password_button_font, cursor="hand2",
                                            command=lambda key=key: update_password_page(key))
            update_password_button.grid(row=i + 1, column=1, sticky="ns", padx=((625 + extraPadding) * (w / 1280), 2 * (w / 1280)),
                                        pady=(2 * (h / 720), 10 * (h / 720)))

            delete_password_button = Button(second_frame, text="Delete Password", bg="#36d5b5", fg="Black",
                                            font=get_password_button_font, cursor="hand2",
                                            command=lambda key=key: delete_password(key))
            delete_password_button.grid(row=i + 1, column=2, sticky="ns", padx=(2 * (w / 1280), 5 * (w / 1280)),
                                        pady=(2 * (h / 720), 10 * (h / 720)))

            i += 2

    use_choice()

    sort_by_label.grid(row=0, column=1, sticky="e")


def about_page():
    global about_me_image

    destroy_frames()
    about_page.about_frame = LabelFrame(root, text="About", fg="White", bg="#2b2b2b", padx=rescale_x(5),
                                        pady=rescale_y(5), font="calibri " + str(rescale_font(10)))
    about_page.about_frame.grid(row=1, column=1, padx=rescale_x(5), pady=rescale_y(2), sticky="nsew")
    about_page.about_frame.grid_columnconfigure(0, weight=1)
    about_page.about_frame.grid_columnconfigure(2, weight=1)
    about_page.about_frame.grid_rowconfigure(1, weight=1)
    about_page.about_frame.grid_rowconfigure(3, weight=1)

    header_label = Label(about_page.about_frame, text="About Titanium Vault", font="Monosten " + str(rescale_font(30)),
                         fg="#009BA3", bg="#2b2b2b", pady=rescale_y(10), justify=CENTER)
    header_label.grid(row=0, column=1)

    info_text = "Titanium Vault is an offline Password Manager that helps you keep strong complex passwords for\n" \
                "each website/app without the hassle of remembering each of them. With the help of strong password\n" \
                "suggestion in Titanium Vault, you do not need to waste any time in coming up with a strong\n" \
                "password yourself. Also while accessing the saved passwords, the passwords are copied to your\n" \
                "clipboard instead of being shown openly to save you from the snooping ones :) \n \n" \
                "The passwords are protected by top-of-the-line hashing and encryption algorithms which make sure\n" \
                "that unauthorized access is nearly impossible. \n \n" \
                "The advantage of an offline password manager over other online counterparts is that your data is\n" \
                "safe from any cyber attack, as all data is stored locally .As long as your physical system\n" \
                "is in safe hands and the master password is not shared with anyone, the passwords will remain safe.\n"

    info_label = Label(about_page.about_frame, text=info_text, font="Monosten " + str(rescale_font(15)),
                       fg="#FEB868", bg="#2b2b2b", pady=rescale_y(10), justify=LEFT)
    info_label.grid(row=2, column=1)

    about_me_image = Image.open("resources/Media/Images/about_me_button.png")
    about_me_image = about_me_image.resize((rescale_font(458), rescale_font(60)), Image.ANTIALIAS)
    about_me_image = ImageTk.PhotoImage(about_me_image)

    def go_to(url):
        webbrowser.open_new_tab(url)

    about_page.about_me_button = Button(about_page.about_frame, image=about_me_image, borderwidth=0, bg="#36d5b5", cursor="hand2",
                             command=lambda: go_to("https://cyantarantula.github.io/My-Portfolio/"))
    about_page.about_me_button.grid(row=4, column=1, pady=rescale_y(5))


login_page()

def destroy_frames():
    try:
        home_page.frequently_used_frame.destroy()
        about_page.about_frame.destroy()
        about_page.about_me_button.destroy()
        profile_page.profile_frame.destroy()
        update_master_password_page.update_master_password_frame.destroy()
        add_website_page.add_website_frame.destroy()
        get_password_page.get_password_frame.destroy()
        update_password_page.update_password_frame.destroy()
    except:
        pass


def quit_app():
    quit = messagebox.askyesno("Titanium Vault", "Are you sure you want to exit?")

    if quit:
        root.quit()


quit_button_image = Image.open("resources/Media/Images/quit_button_transparent.png")
quit_button_image = quit_button_image.resize((rescale_font(50), rescale_font(50)), Image.ANTIALIAS)
quit_button_image = ImageTk.PhotoImage(quit_button_image)

quit_button = Button(root, image=quit_button_image, bg="#36d5b5", command=quit_app, cursor="hand2")
quit_button.place(relx=0.995, rely=0.01, anchor="ne")

root.mainloop()
try:
    root.destroy()
except:
    pass
