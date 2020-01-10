check: access_check.c access_support.c access_support.h
	gcc -Wall -pedantic -Werror access_check.c access_support.c -o access_check -lbsd

interactive: check
	./access_check check testfiles/group.txt testfiles/acl1.txt

batch: check
	./access_check check testfiles/group.txt testfiles/acl1.txt testfiles/batch.txt

bad1: check
	./access_check check

bad2: check
	./access_check check testfiles/group.txt testfiles/acl2.txt testfiles/batch.txt toomanyargs

.PHONY: clean
clean:
	rm -f access_check output.txt