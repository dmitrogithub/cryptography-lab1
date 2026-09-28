import subprocess
from pathlib import Path

exe = Path(__file__).resolve().parents[1] / 'build/kalyna-lab'

def run(lines):
    result = subprocess.run([str(exe)], input='\n'.join(lines) + '\n', text=True,
                            encoding='utf-8', capture_output=True, timeout=90)
    assert result.returncode == 0, result.stderr
    return result.stdout

menu = run(['0'])
assert '1 — Покроково: Калина' in menu
assert '2 — Покроково: AES' in menu
assert '3 — Покроково: CCM із Калиною' in menu
assert '4 — Порівняти швидкість Калини та AES' in menu
assert 'Детальний навчальний огляд' not in menu

kalyna_encrypted = run(['1', '1', '', '', '', '', '', '0'])
assert 'Текст у UTF-8: Hello world!' in kalyna_encrypted
assert 'Початкове додавання з K[0]' in kalyna_encrypted
assert 'РЕЗУЛЬТАТ КАЛИНИ' in kalyna_encrypted
kalyna_cipher = next(line.split('Шифртекст: ', 1)[1] for line in kalyna_encrypted.splitlines()
                     if line.startswith('Шифртекст: '))
kalyna_decrypted = run(['1', '2', '', '', kalyna_cipher, '', '0'])
assert 'Відновлений текст: Hello world!' in kalyna_decrypted
assert 'Зворотний раунд 10 / 10: InvMixColumns' in kalyna_decrypted

aes_encrypted = run(['2', '1', '', '', '', '', '0'])
assert 'Текст у UTF-8: Hello world!' in aes_encrypted
assert 'Раунд 1 / 10: SubBytes' in aes_encrypted
assert 'Матриця AES: 4 рядки x 4 стовпці' in aes_encrypted
aes_cipher = next(line.split('Шифртекст: ', 1)[1] for line in aes_encrypted.splitlines()
                  if line.startswith('Шифртекст: '))
aes_decrypted = run(['2', '2', '', aes_cipher, '', '0'])
assert 'Текст після зняття PKCS#7: Hello world!' in aes_decrypted
assert 'Зворотний раунд 9: InvShiftRows' in aes_decrypted

ccm = run(['3', '1', '2', '', '', '0'])
assert 'Відновлений текст: Hello world! This is Kalyna CCM.' in ccm
assert 'CCM / початковий ланцюжок MAC' in ccm
assert 'CCM / гама = E(K, лічильник)' in ccm
assert 'Перевірка тега: УСПІШНО' in ccm
assert 'Підміну виявлено' in ccm
assert 'РОЗБІР КАЛИНИ' not in ccm

control = run(['3', '1', '1', '', '0'])
assert 'B91A7B8790BBCFCFE65D04E5538E98E2704454C9DD39ADACE0B19D03F6AAB07E' in control

invalid = run(['5', '1', '3', '0'])
assert 'Введіть номер від 0 до 4.' in invalid
assert 'Помилка: Виберіть 1 або 2' in invalid
print('PASS: simplified menu, Kalyna/AES forward and reverse, CCM trace and authentication')

speed = run(['4', '0'])
assert 'Kalyna-128/128' in speed and 'AES-128' in speed
assert 'Kalyna-reference-128-ECB' in speed and 'Kalyna-reference-128-CCM' in speed
print('PASS: speed comparison in menu, including separate reference ECB/CCM')
