# Rozrabiaka reverse proxy
Stworzyłem z kolegami reverse proxy do strony odrabiamy.pl, ponieważ był tam limit urządzeń jakie mogą być zalogowane na jedno konto w tym samym momencie. Potem info o tym się rozniosło na szkołę, więc stworzyliśmy współdzielone konto.
main.go jest głównym kodziorem w tym wszystkim.
encrypt.go służy jedynie do szyfrowania sesji, tak, aby inna osoba z naszej szkoły nie mogła nam zabrać konta :p
zablokowaliśmy możliwości pisania do osób, do klikania na polubienia, dodawania rzeczy do ulubiony itp., jedyne co można było dzięki temu robić to przeglądać stronkę i zadania.
Zrobione w 2 dni, więc kod jest brzydki, ale potrzebowaliśmy wszyscy zadań z niemieckiego, a subskrypcja droga...