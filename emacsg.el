(defconst oauth-unreserved-chars
  '(?a ?b ?c ?d ?e ?f ?g ?h ?i ?j ?k ?l
       ?m ?n ?o ?p ?q ?r ?s ?t ?u ?v ?w ?x ?y ?z
       ?A ?B ?C ?D ?E ?F ?G ?H ?I ?J ?K ?L
       ?M ?N ?O ?P ?Q ?R ?S ?T ?U ?V ?W ?X ?Y ?Z
       ?0 ?1 ?2 ?3 ?4 ?5 ?6 ?7 ?8 ?9
       ?- ?. ?_ ?~ ))

(defun oauth-hexify (string)
  (mapconcat (lambda (byte)
               (if (memq byte oauth-unreserved-chars)
                   (char-to-string byte)
                 (format "%%%02X" byte)))
             (if (multibyte-string-p string)
                 (encode-coding-string string 'utf-8)
               string)
             ""))

(defun time-in-secs ()
  (format "%d" (ftruncate (float-time (current-time)))))


(defun kvput (alist key val)
  (let ((old (assoc key alist)))
    (cond ((null old)
	   (cons (cons key val) alist))
	  (t
	   (setf (cdr old) val)
	   alist))))

(defun kvget (alist key)
  (cdr (assoc key alist)))


(defvar *currnet_oauth_token* nil)
(defvar *current_oauth_token_secret* nil)

;;; these are setq in the file keys.el (not under source control...)
(defvar *oauth_consumer_key*)
(defvar *oauth_consumer_secret*)

(defun check-sig (key secret base-string)
  (oauth-hexify
   (base64-encode-string
    (hmac-sha1 (concat (oauth-hexify key)
		       "&"
		       (oauth-hexify secret))
	       base-string))))




(defun oauth1 ()
  (let ((args nil)
	(url "https://www.google.com/accounts/OAuthGetRequestToken"))
    (setq args (kvput args "oauth_callback" "oob"))
    ;;(setq args (kvput args "oauth_callback" "http://localhost/saveauth.php"))
    (setq args (kvput args "scope" "http://docs.google.com/feeds/"))

    (let ((vals (do-oauth url args
			  *oauth_consumer_key* *oauth_consumer_secret*
			  (make-hmac-key *oauth_consumer_secret* "")
			  nil)))
      (let ((oauth_token (cdr (assoc "oauth_token" vals))))
	(when oauth_token
	  (setq *current_oauth_token* (kvget vals "oauth_token"))
	  (setq *current_oauth_token_secret* (kvget vals "oauth_token_secret"))

	  (print (cons "vals =" vals))
	  (print nil)
	  (let ((url (concat "https://www.google.com/"
			     "accounts/OAuthAuthorizeToken"
			     "?oauth_token="
			     (oauth-hexify oauth_token))))
	    (browse-url url)))))))
      
(defun google-get-access-token (oauth_token oauth_token_secret oauth_verifier)
  (let ((args nil)
	(url "https://www.google.com/accounts/OAuthGetAccessToken"))
    (setq args (kvput args "oauth_token" oauth_token))
    (setq args (kvput args "oauth_verifier" oauth_verifier))
    (let ((vals (do-oauth url args
			  *oauth_consumer_key* oauth_token_secret
			  (make-hmac-key *oauth_consumer_secret*
					 oauth_token_secret)
			  nil)))
      vals)))

(defvar *access_oauth_token*)
(defvar *access_oauth_token_secret*)

(defun oauth2 (verifier)
  (let ((vals (google-get-access-token
	       *current_oauth_token*
	       *current_oauth_token_secret* 
	       verifier)))
    (setq *access_oauth_token* (kvget vals "oauth_token"))
    (setq *access_oauth_token_secret* (kvget vals "oauth_token_secret"))
    vals))


(defun google-get (url)
  (let ((args nil)
	(extra-hdrs nil))
    (setq args (kvput args "oauth_token" *access_oauth_token*))
    (setq extra-hdrs (kvput extra-hdrs "GData-Version" "3.0"))
    (let ((vals (do-oauth url args
			  *oauth_consumer_key*
			  *access_oauth_token_secret*
			  (make-hmac-key *oauth_consumer_secret*
					 *access_oauth_token_secret*)
			  extra-hdrs)))
      vals)))

(defun make-hmac-key (key secret)
  (concat (oauth-hexify key) "&" (oauth-hexify secret)))

(defun urlparams (url)
  (let ((idx (string-match "?" url))
	(result nil))
    (when idx
      (dolist (keyval (split-string (substring url (+ idx 1)) "&"))
	(let ((idx2 (string-match "=" keyval)))
	  (when idx2
	    (let ((key (url-unhex-string (substring keyval 0 idx2)))
		  (val (url-unhex-string (substring keyval (+ idx2 1)))))
	      (setq result (cons (cons key val) result)))))))
    result))



(defun do-oauth (url args-raw consumer_key consumer_secret hmac-key
		     extra-hdrs-raw)
  (let ((vals (copy-alist args-raw))
	(base-vals nil)
	(extra-hdrs (copy-alist extra-hdrs-raw))
	(nonce (base64-encode-string (number-to-string (random t))))
	(base-string nil)
	(auth nil)
	(sig nil)
	(req-url nil)
	(result nil)
	(timestamp (time-in-secs))
	(url-request-method "GET")
	(base-url nil))

    ;;(setq nonce "d7cb7ccf54235d176670dcf8786070a9")
    ;;(setq timestamp "1262481672")

    (setq vals (kvput vals "oauth_consumer_key" consumer_key))
    (setq vals (kvput vals "oauth_nonce" nonce))
    (setq vals (kvput vals "oauth_signature_method" "HMAC-SHA1"))
    (setq vals (kvput vals "oauth_timestamp" timestamp))
    (setq vals (kvput vals "oauth_version" "1.0"))

    (setq base-vals (copy-alist vals))

    (dolist (keyval (urlparams url))
      (setq base-vals (kvput base-vals (car keyval) (cdr keyval))))

    (setq base-vals (sort base-vals (lambda (a b) (string< (car a) (car b)))))

    (setq base-url (if (string-match "\\([^?]+\\)" url)
		       (match-string 1 url)
		     url))

    (setq base-string
	  (concat (oauth-hexify url-request-method)
		  "&"
		  (oauth-hexify base-url)
		  "&"
		  (oauth-hexify
		   (mapconcat (lambda (arg)
				(concat (oauth-hexify (car arg))
					"="
					(oauth-hexify (cdr arg))))
			      base-vals "&"))))
    (princ base-string)
    (if (null hmac-key)
	(setq hmac-key (make-hmac-key consumer_key consumer_secret)))
    (setq sig (base64-encode-string (hmac-sha1 hmac-key base-string)))
  
    (setq vals (kvput vals "oauth_signature" sig))
    (setq auth (concat "OAuth "
		       (mapconcat (lambda (arg)
				    (concat (oauth-hexify (car arg))
					    "=\""
					    (oauth-hexify (cdr arg))
					    "\""))
				  vals ", ")))
    (setq extra-hdrs (kvput extra-hdrs "Authorization" auth))

    (setq req-url url)
    (let ((url-request-data nil)
	  (url-request-extra-headers  extra-hdrs))
      (princ (format "\n\nURL %s\n\n" req-url))
      (princ (format "\n\nhdrs %s\n\n" url-request-extra-headers))
      (let ((buf (url-retrieve-synchronously req-url)))
	(save-excursion
	  (set-buffer buf)
	  (goto-char (point-min))
	  (search-forward "\n\n")
	  (dolist (keyval (split-string (buffer-substring
					 (point)
					 (point-max))
					"&"))
	    (let ((idx (string-match "=" keyval)))
	      (when idx
		(let ((key (substring keyval 0 idx))
		      (val (substring keyval (+ idx 1))))
		  (setq result (cons (cons key (url-unhex-string val))
				     result))))))
	  (ignore-errors (kill-buffer "last"))
	  (rename-buffer "last"))))
    result))

(defun gdocs-list ()
  (google-get "http://docs.google.com/feeds/default/private/full")
  )

(defun get-doc ()
  (google-get "http://docs.google.com/feeds/download/documents/Export?docId=0AdjoyZgGOu2gZHQ3NnEzOF81N2hmcjlza2dx&exportFormat=html"))


(defun do-bolds ()
  (goto-char (point-min))
  (while (re-search-forward "<b\\>" nil t)
    (let ((start (match-beginning 0)))
      (when (search-forward ">" nil t)
	(delete-region start (point))
	(when (re-search-forward "</b>" nil t)
	  (delete-region (match-beginning 0) (point))
	  (put-text-property start (point) 'face 'bold))))))

(defun do-newlines ()
  (goto-char (point-min))
  (while (re-search-forward "\r" nil t)
    (replace-match ""))

  (goto-char (point-min))
  (when (re-search-forward "[^ \t\r\n]" nil t)
    (delete-region (point-min) (- (point) 1 )))

  (goto-char (point-min))
  (while (search-forward "\n" nil t)
    (let ((start (point)))
      (skip-chars-forward " \t\n")
      (let ((end (point)))
	(delete-region start end))))

  )

(defun do-bullets ()
  (goto-char (point-min))
  (while (re-search-forward "</?[uo]l>" nil t)
    (replace-match ""))

  (goto-char (point-min))
  (while (re-search-forward "<li>" nil t)
    (let ((start (match-beginning 0)))
      (skip-chars-forward " \t\n")
      (delete-region start (point))
      (insert "* ")
      (when (re-search-forward "</li>" nil t)
	(delete-region (match-beginning 0) (match-end 0))
	(skip-chars-backward " \t\n")
	(let ((end (point)))
	  (skip-chars-forward " \t\n")
	  (delete-region end (point)))
	(insert hard-newline)))))

(defun do-brs ()
  (goto-char (point-min))
  (while (re-search-forward "<[ \t]*br[ \t]*/?>" nil t)
    (replace-match hard-newline)
    (let ((start (point)))
      (skip-chars-forward " \t\n")
      (delete-region start (point)))))

(defun do-divs ()
  (goto-char (point-min))
  (while (re-search-forward "<div" nil t)
    (let ((start (match-beginning 0)))
      (search-forward ">" nil t)
      (delete-region start (point)))
    (when (re-search-forward "</div>" nil t)
      (delete-region (match-beginning 0) (match-end 0))
      (insert "<br>"))))

(defun conv ()
  (interactive)
  (save-excursion
    (set-buffer (get-buffer "new"))
    (set-buffer (get-buffer "new"))
    (delete-region (point-min) (point-max))
    (enriched-mode 1)
    (insert-buffer "last")
    (convert-to-enriched)))

(defun convert-to-enriched ()
  (goto-char (point-min))
  (when (re-search-forward "<[ \t]*body" nil t)
    (when (re-search-forward ">" nil t)
      (delete-region (point-min) (point))))
  
  (when (re-search-forward "</[ \t]*body" nil t)
    (delete-region (match-beginning 0)  (point-max)))
  
  (goto-char (point-min))
  (while (re-search-forward "<!--" nil t)
    (let ((start (match-beginning 0)))
      (when (re-search-forward "-->" nil t)
	(delete-region start (match-end 0)))))
  
  (do-newlines)
  (do-bolds)
  (do-bullets)
  (do-divs)
  (do-brs)
  
  (fill-region (point-min) (point-max))
  
  )
