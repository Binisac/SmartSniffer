from tkinter import BOTTOM, X, BOTH, COMMAND
from tkinter import Tk, ttk
from tkinter.messagebox import showinfo, showerror
from os import listdir
import sys
import winreg
import os
import random

if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

os.chdir(application_path)


class RegistryManager:
    def __init__(self, hive, subkey):
        self.hive = hive
        self.subkey = subkey

    def check_value_exists(self, value_name):
        try:
            key = winreg.OpenKey(self.hive, self.subkey)
            winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            return False
        except PermissionError:
            showerror(title="Ошибка",
                      message="Ошибка: Нет прав доступа к реестру.")
            return False

    def set_value(self, value_name, value_data, value_type=winreg.REG_SZ):
        try:
            key = winreg.OpenKey(self.hive, self.subkey, 0, winreg.KEY_WRITE)
        except FileNotFoundError:
            key = winreg.CreateKey(self.hive, self.subkey)

        winreg.SetValueEx(key, value_name, 0, value_type, value_data)
        winreg.CloseKey(key)

    def ensure_value(self, value_name, value_data, value_type=winreg.REG_SZ):
        self.set_value(value_name, value_data, value_type)


script_dir = os.path.dirname(os.path.abspath(__file__))


def file_selection():
    global txt_files
    txt_files = [i for i in listdir() if i.lower().endswith(".txt")]
    if not txt_files:
        info = ttk.Label(text="В текущей директории нет txt файлов.")  # noqa: E501
        info.grid(row=2, column=0, columnspan=2)

    else:
        info = ttk.Label(text="Выберите основу:")  # noqa: E501
        info.grid(row=2, column=0, columnspan=2)
        if not setup123:
            for idx, filename in enumerate(txt_files):
                display_name = filename.replace(".txt", "").replace(".exe", "")
                setup12 = ttk.Button(
                    text=display_name,
                    command=lambda f=filename: razbor_dampa(f)
                    )
                setup12.grid(row=idx+3, column=0, columnspan=2)
                setup123.append(setup12)
                btn.config(text="Обновить")
        else:
            info.destroy()
            for setup12 in setup123:
                setup12.destroy()
            for idx, filename in enumerate(txt_files):
                txt_files = [i for i in listdir() if i.lower().endswith(".txt")]
                display_name = filename.replace(".txt", "").replace(".exe", "")
                setup12 = ttk.Button(
                    text=display_name,
                    command=lambda f=filename: razbor_dampa(f)
                )

                setup12.grid(row=idx+3, column=0, columnspan=2)
                setup123.append(setup12)


def razbor_dampa(filename):
    if filename:
        sniffer = [
            (i.rstrip()[4:-6] if i.rstrip().endswith(":90:00")
             else i.rstrip()[4:])
            for i in open(filename).readlines()
            if i.startswith("<<< ")
        ]
        if sniffer:
            primary = bytes.fromhex(
                "".join([i for i in sniffer if (i[:5] == "30:22")][:1]).replace(  # noqa: E501
                    ":", " "
                    )
            )[:36]

            masks = bytes.fromhex(
                 "".join([i for i in sniffer if (i[:5] == "30:36")][:1]).replace(  # noqa: E501
                    ":", " "
                    )
            )[:56]

            name = "Empty"
            header = b""
            headersign = [i for i, j in enumerate(
                sniffer) if (j[:5] == "30:82")]
            if headersign:
                headersign = headersign[0]
                header = bytes.fromhex(sniffer[headersign].replace(":", " "))
                headerlen = int.from_bytes(header[2:4], "big") + 4
                if len(header) > 16:
                    name = "ExJacartaPro"
                    for i in range(headersign + 1, len(sniffer)):
                        if len(header) < (headerlen + 240):
                            header += bytes.fromhex(
                                sniffer[i].replace(":", " "))
                        else:
                            break
                    for i in range(16, len(header) - 479, 16):
                        if header[i: i + 240] == header[i + 240: i + 480]:
                            header = b"".join((header[:i], header[i + 240:]))
                            break
                elif len(sniffer[headersign + 1]) != len(sniffer[headersign + 2]):  # noqa: E501
                    name = "ExEsmart"
                    for i in range(headersign + 3, len(sniffer), 3):
                        if len(header) < headerlen:
                            header += bytes.fromhex(
                                sniffer[i].replace(":", " "))
                        else:
                            break
                else:
                    name = "ExJacartaLite"
                    for i in range(headersign + 1, len(sniffer)):
                        if len(header) < headerlen:
                            header += bytes.fromhex(
                                sniffer[i].replace(":", " "))
                        else:
                            break
            name = (
                b"0"
                + (len(name) + 2).to_bytes(1, "little")
                + b"\x16"
                + len(name).to_bytes(1, "little")
                + bytes(name, "ascii")
            )
            rng = str(random.randint(1000, 9999))
            os.mkdir(rng)

            if primary:
                open("primary.key", "xb").write(primary) and os.replace(
                    "primary.key", rng + "/primary.key"
                )
            if masks:
                open("masks.key", "xb").write(masks) and os.replace(
                    "masks.key", rng + "/masks.key"
                )
            if header:
                open("header.key", "xb").write(header) and os.replace(
                    "header.key", rng + "/header.key"
                )
            open("name.key", "xb").write(name) and os.replace(
                "name.key", rng + "/name.key"
            )
            showinfo(title="Успешно", message="Папка с номером " + rng)
            os.startfile(os.getcwd())
        else:
            showinfo(title="Ошибка", message="Файл не корректен")
    else:
        showinfo(title="Ошибка", message="Файл не найден")


def reestr_onn():
    global application_path
    if __name__ == "__main__":

        registry_manager = RegistryManager(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")
        registry_manager.ensure_value("LoadAppInit_DLLs", 1, winreg.REG_DWORD)
        registry_manager.ensure_value(
            "RequireSignedAppInit_DLLs", 0, winreg.REG_DWORD)
        path_to = application_path + r"\SmartcardSniffer.dll"
        registry_manager.ensure_value("AppInit_DLLs", path_to, winreg.REG_SZ)

        registry_manager = RegistryManager(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows")  # noqa: E501
        registry_manager.ensure_value("LoadAppInit_DLLs", 1, winreg.REG_DWORD)
        registry_manager.ensure_value(
            "RequireSignedAppInit_DLLs", 0, winreg.REG_DWORD)
        path_to = application_path + r"\SmartcardSniffer32.dll"
        registry_manager.ensure_value("AppInit_DLLs", path_to, winreg.REG_SZ)

    showinfo(
        title="Успешно",
        message="Включено! Перезагрузите компьютер. Далее - необходимо произвести обмен с ЭЦП")  # noqa: E501


def reestr_offf():

    if __name__ == "__main__":

        registry_manager = RegistryManager(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows")
        registry_manager.ensure_value("LoadAppInit_DLLs", 0, winreg.REG_DWORD)
        registry_manager.ensure_value("AppInit_DLLs", "", winreg.REG_SZ)

        registry_manager = RegistryManager(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows")  # noqa: E501
        registry_manager.ensure_value("LoadAppInit_DLLs", 0, winreg.REG_DWORD)
        registry_manager.ensure_value("AppInit_DLLs", "", winreg.REG_SZ)

    showinfo(
        title="Успешно",
        message="Отключено!")  # noqa: E501


def CertFix():
    global application_path
    os.chdir(r".\Dist\CertFix")
    os.startfile(r".\cert.bat")
    os.chdir(application_path)


def Tokens():
    #print(sys.executable)
    os.startfile(r".\Dist\Tokens.exe")


root = Tk()
root.title("Работа с ЭЦП")
root.geometry("300x250")

root.rowconfigure(100, weight=1)
root.columnconfigure(0, weight=1)

setup123 = []

setup = ttk.Button(root, text="Включить", command=reestr_onn)
setup.grid(row=0, column=0,sticky="ns", ipadx=37)

setup2 = ttk.Button(root, text="Выключить", command=reestr_offf)
setup2.grid(row=0, column=1,sticky="ns", ipadx=37)


btn = ttk.Button(root, text="Разобрать Дамп", command=file_selection)
btn.grid(row=1, column=0, columnspan=2,sticky="ns", ipadx=100)

btnc = ttk.Button(text="Открыть CertFix", command=CertFix)
btnc.grid(row=100, column=0, columnspan=2,sticky="s", ipadx=100)

btnt = ttk.Button(text="Открыть Tokens", command=Tokens)
btnt.grid(row=101, column=0, columnspan=2,sticky="s", ipadx=100)


root.mainloop()  # type: ignore
