from pickle import NONE
import dns.rdatatype
import dns.resolver
import smtplib
import sys

eMailList = []
eMailForComparing = "yoifsangdsDSFkjdk@"

def StartCheck(email : str) -> None:
    print("\n\t==== checking email " + email + "...\n")
    tempEmail = eMailForComparing + email.split("@")[-1]
    resp = None
    try:
        resp = dns.resolver.resolve(email.split("@")[-1], "MX")
    except:
        print("\tNO answer for pbcdc.cn. IN MX...")
        return
    isValid = False
    for ele in resp:
        server = str(ele).split(' ')[-1]
        print("\tServer : " + server)
        # Check server configuration
        print("\tCheck for server configuration...")
        smtp = smtplib.SMTP(server, timeout=100)
        print("\t>>> send ehlo")
        print("\t" + str(smtp.ehlo()))
        print("\t>>> send smtp.mail('')")
        print("\t" + str(smtp.mail("")))
        print("\t>>> send smtp.rcpt for check")
        temp = smtp.rcpt(tempEmail)
        print("\t" + str(temp) + "\n")
        if 250 == temp[0]:
            print("\tThe recipient server is configured to accept all.")
            return
        # Check if the target email is valid
        print("\tCheck for target email address...")
        smtp = smtplib.SMTP(server, timeout=100)
        print("\t>>> send ehlo")
        print("\t" + str(smtp.ehlo()))
        print("\t>>> send smtp.mail('')")
        print("\t" + str(smtp.mail("")))
        print("\t>>> send smtp.rcpt for check")
        temp = smtp.rcpt(email)
        print("\t" + str(temp) + "\n")
        if 250 == temp[0]:
            isValid = True
            break
        smtp.close()
    if isValid:
        print("\tRESULT : {0} is existed :)".format(email))
    else:
        print("\tRESULT : {0} is NOT existed :)".format(email))

if __name__ == "__main__":
    if len(sys.argv) == 1:
        for addr in eMailList:
            StartCheck(addr)
    else:
        StartCheck(sys.argv[1])
