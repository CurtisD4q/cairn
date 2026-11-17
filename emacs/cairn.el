;;; cairn.el --- Open cairn, a security workbench, from Emacs -*- lexical-binding: t; -*-

;; Version: 0.1.0
;; Package-Requires: ((emacs "27.1"))
;; Keywords: tools, processes, terminals

;;; Commentary:
;;
;; M-x cairn opens cairn, the terminal workbench for security work.
;;
;; If mint.el (from Mint-Interfaces) is installed, cairn is started with
;; it, so you get its handover mode in terminal Emacs, Emacs keys, and
;; colours that match your theme.  Without mint.el, cairn runs in a `term'
;; buffer with Emacs keys, and nothing else needs installing.
;;
;; M-x cairn-cases opens the folder of your cases in Dired.  Reports saved
;; from cairn are Markdown files there, and open like any other file.

;;; Code:

(require 'term)

(defgroup cairn nil
  "Open cairn from Emacs."
  :group 'tools
  :prefix "cairn-")

(defcustom cairn-program "cairn"
  "The cairn program: a name on `exec-path', or a path."
  :type 'string)

(defcustom cairn-key-profile "emacs"
  "Keys cairn uses when it runs in a `term' buffer, set as MINT_KEYS.
One of \"emacs\", \"vim\" or \"default\".  With mint.el installed, its own
`mint-key-profile' applies instead."
  :type '(choice (const "emacs") (const "vim") (const "default")))

(defcustom cairn-home nil
  "Folder where cairn keeps its cases, or nil for its usual place.
Set as CAIRN_HOME for the programs Emacs starts."
  :type '(choice (const :tag "Usual place" nil) directory))

(defun cairn--executable ()
  "Return the full path of `cairn-program', or signal a plain-words error."
  (let ((expanded (expand-file-name cairn-program)))
    (cond ((and (file-executable-p expanded) (not (file-directory-p expanded))) expanded)
          ((executable-find cairn-program))
          (t (user-error "Cannot find the program \"%s\".  Install cairn, or set `cairn-program'"
                         cairn-program)))))

(defun cairn--environment ()
  "Environment entries Emacs gives cairn."
  (delq nil
        (list (and cairn-home (format "CAIRN_HOME=%s" (expand-file-name cairn-home)))
              (format "MINT_KEYS=%s" cairn-key-profile)
              "TERM=xterm-256color"
              "COLORTERM=truecolor")))

;;;###autoload
(defun cairn ()
  "Open cairn."
  (interactive)
  (let ((exe (cairn--executable))
        (process-environment (append (and cairn-home (list (format "CAIRN_HOME=%s" (expand-file-name cairn-home))))
                                     process-environment)))
    (if (and (require 'mint nil t) (fboundp 'mint-run))
        (mint-run exe "cairn")
      (cairn--in-term exe))))

(defun cairn--in-term (exe)
  "Run EXE in a `term' buffer."
  (let* ((process-environment (append (cairn--environment) process-environment))
         (buf (get-buffer "*cairn*")))
    (if (and buf (get-buffer-process buf) (process-live-p (get-buffer-process buf)))
        (switch-to-buffer buf)
      (setq buf (make-term "cairn" exe))
      (switch-to-buffer buf)
      (term-char-mode))))

(defun cairn--cases-directory ()
  "The folder holding cairn's cases."
  (expand-file-name
   "cases"
   (or cairn-home
       (let ((data (getenv "XDG_DATA_HOME")))
         (if (and data (not (string-empty-p data)))
             (expand-file-name "cairn" data)
           (expand-file-name "~/.local/share/cairn"))))))

;;;###autoload
(defun cairn-cases ()
  "Open the folder of cairn's cases and saved reports in Dired."
  (interactive)
  (let ((dir (cairn--cases-directory)))
    (unless (file-directory-p dir)
      (user-error "No cases yet.  Open cairn first with M-x cairn"))
    (dired dir)))

(provide 'cairn)
;;; cairn.el ends here
