 # Variant 6
 
Algorithm AES

Метод encrypt виконує шифрування переданого тексту в режимі CBC. Використовується доповнення тексту до кратного 16 байтам та поділ його на блоки. Для кожного блоку виконується шифрування та зберігається попередній зашифрований блок для використання у наступному раунді.
Метод decrypt виконує дешифрування переданого зашифрованого тексту в режимі CBC. Відновлює оригінальний текст за допомогою обернених операцій.

Signature algorithm Nyberg-Rueppel 

Метод generate_keys генерує пару приватного та публічного ключів за допомогою функції gen_keypair з бібліотеки fastecdsa(pip install fastecdsa - якщо не встановлена).
Метод sign приймає повідомлення, яке потрібно підписати. Спочатку обчислюється хеш повідомлення, а потім генерується випадкове число k для підпису. В циклі виконується обчислення підпису.
Метод verify приймає повідомлення та підпис і перевіряє його достовірність.