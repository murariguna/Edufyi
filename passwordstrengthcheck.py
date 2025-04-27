import re
def strength(password):
    scr=0
    if len(password) < 8:
        print("Paswword is too short the lenfth of password should be atleast 8")
    else:
        scr=scr+1

    
    if re.search(r'[A-Z]',password):
        scr=scr+1
    else:
        print("No UPPERCASE LETTERS in the Password")


    if re.search(r'[a-z]',password):
        scr=scr+1
    else:
        print("No LOWERCASE LETTERS in the Password") 

    if re.search(r'\d',password):
        scr=scr+1
    else:
        print("No DIGITS in the Password")      

    if re.search(r'[\W_]',password):
        scr=scr+1
    else:
        print("No SPECIAL CHERECTERS in the Password")

    easypass=['password', '123456', 'qwerty', 'letmein', 'admin','asdfgh','zxcvbn']

    if password.lower() in easypass:
        print("Avoid common words or sequences.")


    if scr <= 2:
        print('you password is "WEAK",please rewrite your password ')
    elif scr == 3 or scr == 4:
        print('you password is "WEAK",can be improved further for better protection ')
    else:
        print('you password is "STRONG"')


ex=input("enter your PASSWORD:")
strength(ex)