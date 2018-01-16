/* ssl_server.c
 *
 * Copyright (c) 2000 Sean Walton and Macmillan Publishers.  Use may be in
 * whole or in part in accordance to the General Public License (GPL).
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
*/

/*****************************************************************************/
/*** ssl_server.c                                                          ***/
/***                                                                       ***/
/*** Demonstrate an SSL server.                                            ***/
/*****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <arpa/inet.h>

#define FAIL    -1
#define FILE_SIZE	100

/*---------------------------------------------------------------------*/
/*--- OpenListener - create server socket                           ---*/
/*---------------------------------------------------------------------*/
int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, &addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitServerCTX - initialize SSL server  and create context     ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();		/* load & register all cryptos, etc. */
    SSL_load_error_strings();			/* load all error messages */
    method = SSLv23_server_method();		/* create new server-method instance */
    ctx = SSL_CTX_new(method);			/* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/*---------------------------------------------------------------------*/
/*--- LoadCertificates - load from files.                           ---*/
/*---------------------------------------------------------------------*/
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	/* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out certificates.                           ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

/*---------------------------------------------------------------------*/
/*--- Servlet - SSL servlet (contexts can be shared)                ---*/
/*---------------------------------------------------------------------*/
void Servlet(SSL* ssl){	/* Serve the connection -- threadable */   
	int sd;
	char file_name[32];
	FILE *fp;
	int len;
	char *data;
	int sent;

	memset(file_name, 0, sizeof(file_name));

    if ( SSL_accept(ssl) == FAIL )					/* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);						/* get any certificates */
        //bytes = SSL_read(ssl, buf, sizeof(buf));	/* get request */
        //if ( bytes > 0 )
        //{
		sprintf(file_name, "garbage_files/%i.gar", FILE_SIZE);
		fp = fopen(file_name, "rb");
		len = FILE_SIZE; 
		data = malloc(len + 1);
		if(data == NULL){
			printf("Malloc Failed\n");
			exit(0);
		}
		fread(data, len, 1, fp); 
		data[len] = '\0';
		printf("Writing %i bytes to fd\n", FILE_SIZE);
            	sent = SSL_write(ssl, data, FILE_SIZE);	/* send reply */
		if (sent != FILE_SIZE){
			perror("SSL_WRITE");
		}
        //}
        //else
        //    ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);					/* get socket connection */
    SSL_free(ssl);							/* release SSL state */
    close(sd);
    fclose(fp);								/* close connection */
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL socket server.                              ---*/
/*---------------------------------------------------------------------*/
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    char *portnum;
    char *addr_buf;
    uint16_t port;
    char cwd[1024];

    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }

	getcwd(cwd, sizeof(cwd));
	strcpy(cwd + strlen(cwd), "/tls_server");
	printf("New Directory: %s\n", cwd);
	chdir(cwd); 


    portnum = strings[1];
    ctx = InitServerCTX();								/* initialize SSL */
    LoadCertificates(ctx, "pem_files/certificate.pem", "pem_files/key.pem");	/* load certs */
    server = OpenListener(atoi(portnum));				/* create server socket */
    while (1)
    {   struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, &addr, &len);		/* accept connection as usual */

	addr_buf = inet_ntoa(addr.sin_addr);
	if (addr_buf == NULL){
		perror("inet_ntoa failure");
		exit(0);
	}
	port = ntohs(addr.sin_port);
        printf("Connection: %s:%" PRIu16 "\n", addr_buf, port);
        ssl = SSL_new(ctx);         					/* get new SSL state with context */
        SSL_set_fd(ssl, client);						/* set connection socket to SSL state */
        Servlet(ssl);									/* service connection */
    }
    close(server);										/* close server socket */
    SSL_CTX_free(ctx);									/* release context */
}