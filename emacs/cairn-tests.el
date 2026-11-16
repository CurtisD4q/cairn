;;; cairn-tests.el --- Tests for cairn.el -*- lexical-binding: t; -*-

(require 'ert)
(require 'cl-lib)
(load (expand-file-name "cairn.el" (file-name-directory (or load-file-name buffer-file-name))) nil t)

(ert-deftest cairn-missing-program-says-so ()
  (let ((cairn-program "definitely-not-installed-cairn"))
    (should-error (cairn--executable) :type 'user-error)))

(ert-deftest cairn-finds-a-program-by-path ()
  (let ((cairn-program (executable-find "sh")))
    (should (equal (cairn--executable) cairn-program))))

(ert-deftest cairn-environment ()
  (let ((cairn-key-profile "vim") (cairn-home "/tmp/c"))
    (should (member "MINT_KEYS=vim" (cairn--environment)))
    (should (member "CAIRN_HOME=/tmp/c" (cairn--environment))))
  (let ((cairn-home nil))
    (should-not (cl-some (lambda (e) (string-prefix-p "CAIRN_HOME" e)) (cairn--environment)))))

(ert-deftest cairn-uses-mint-when-it-is-installed ()
  (let ((cairn-program (executable-find "sh")) calls)
    (cl-letf (((symbol-function 'require) (lambda (feature &rest _) (eq feature 'mint)))
              ((symbol-function 'mint-run) (lambda (&rest args) (push args calls))))
      (cairn))
    (should (equal calls (list (list (executable-find "sh") "cairn"))))))

(ert-deftest cairn-falls-back-to-a-term-buffer ()
  (let ((cairn-program (executable-find "sh")) seen env)
    (cl-letf (((symbol-function 'require) (lambda (&rest _) nil))
              ((symbol-function 'make-term) (lambda (name prog &rest _) (setq seen (list name prog) env process-environment) (get-buffer-create " *fake*")))
              ((symbol-function 'switch-to-buffer) #'ignore)
              ((symbol-function 'term-char-mode) #'ignore))
      (cairn))
    (should (equal seen (list "cairn" (executable-find "sh"))))
    (should (member "MINT_KEYS=emacs" env))))

(ert-deftest cairn-cases-directory ()
  (let ((cairn-home "/tmp/cairn-x"))
    (should (equal (cairn--cases-directory) "/tmp/cairn-x/cases")))
  (let ((cairn-home nil) (process-environment (cons "XDG_DATA_HOME=/tmp/xdg" process-environment)))
    (should (equal (cairn--cases-directory) "/tmp/xdg/cairn/cases"))))

(ert-deftest cairn-cases-without-cases-says-so ()
  (let ((cairn-home (make-temp-name "/tmp/no-such-cairn-")))
    (should-error (cairn-cases) :type 'user-error)))

(provide 'cairn-tests)
;;; cairn-tests.el ends here
