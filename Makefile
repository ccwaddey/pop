all: popd authpop wrkrpop

popd: pop.c imsgpop.h
	cc -ggdb -Wall -o popd pop.c -lutil -levent

authpop: authpop.c imsgpop.h
	cc -ggdb -Wall -o authpop authpop.c -lutil -levent -ltls

wrkrpop: wrkrpop.c imsgpop.h
	cc -ggdb -Wall -o wrkrpop wrkrpop.c -lutil -levent -lcrypto

tags:
	etags wrkrpop.c authpop.c pop.c imsgpop.h

wc:
	wc *.[ch]
