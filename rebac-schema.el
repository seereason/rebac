;;; rebac.el --- major mode for rebac-schema  -*- lexical-binding: t; -*-

;;       * the name of our face *
(defface font-lock-operator-face
  '((((class color)
       :background "darkseagreen2")))
  "Basic face for highlighting."
  :group 'basic-faces)
(defvar font-lock-operator-face 'font-lock-operator-face)

;; You'll have a hard time missing these colors
(set-face-foreground 'font-lock-operator-face "brown")
(set-face-background 'font-lock-operator-face 'nil)

(defconst rebac-schema--font-lock-defaults
  (let ((keywords '("definition" "relation" "permission"))
        (operators '("->" "+" "&" "|" "-" "="))
        (types '()))
    `(((,(rx-to-string `(: (or ,@keywords))) 0 font-lock-keyword-face)
       ("\\([[:word:]]+\\)\s*(" 1 font-lock-function-name-face)
       (,(rx-to-string `(: (or ,@types))) 0 font-lock-type-face)
       (,(rx-to-string `(: (or ,@operators))) 0 font-lock-operator-face)
       ))))

(defvar rebac-schema-mode-syntax-table
  (let ((st (make-syntax-table)))
    (modify-syntax-entry ?\{ "(}" st)
    (modify-syntax-entry ?\} "){" st)
    (modify-syntax-entry ?\( "()" st)

    ;; - and _ are word constituents
    (modify-syntax-entry ?_ "w" st)
    (modify-syntax-entry ?- "w" st)

    ;; both single and double quotes makes strings
    (modify-syntax-entry ?\" "\"" st)
    (modify-syntax-entry ?' "'" st)

    ;; <# #> denotes a multi-line comment
    (modify-syntax-entry ?/ ". 124b" st)
    (modify-syntax-entry ?* ". 23" st)
    (modify-syntax-entry ?\n "> b" st)

    ;; '==' as punctuation
    ;; (modify-syntax-entry ?= ".")
    ;; '->' as punctuation
    ;;(modify-syntax-entry ?% "." st)

    st))

(defun rebac-schema-indent-line ()
  "Indent current line."
  (let (indent
        boi-p                           ;begin of indent
        move-eol-p
        (point (point)))                ;lisps-2 are truly wonderful
    (save-excursion
      (back-to-indentation)
      (setq indent (car (syntax-ppss))
            boi-p (= point (point)))
      ;; don't indent empty lines if they don't have the in it
      (when (and (eq (char-after) ?\n)
                 (not boi-p))
        (setq indent 0))
      ;; check whether we want to move to the end of line
      (when boi-p
        (setq move-eol-p t))
      ;; decrement the indent if the first character on the line is a
      ;; closer.
      (when (or (eq (char-after) ?\))
                (eq (char-after) ?\}))
        (setq indent (1- indent)))
      ;; indent the line
      (delete-region (line-beginning-position)
                     (point))
      (indent-to (* rebac-schema-basic-offset indent)))
    (when move-eol-p
      (move-end-of-line nil))))

(defvar rebac-schema-mode-abbrev-table nil
  "Abbreviation table used in `rebac-schema-mode' buffers.")

(define-abbrev-table 'rebac-schema-mode-abbrev-table
  '())

;;;###autoload
(define-derived-mode rebac-schema-mode prog-mode "rebac-schema"
  "Major mode for rebac schema files."
  :abbrev-table rebac-schema-mode-abbrev-table
  :syntax-table rebac-schema-mode-syntax-table

  (setq font-lock-defaults rebac-schema--font-lock-defaults)
  (setq comment-start "/* " )
  (setq comment-end " */")
;;  (setq-local comment-start "#")
  (setq comment-start-skip "/\\*+[ \t]*\\|//+[ \t]*")
  (setq rebac-schema-basic-offset 2)
  (setq-local indent-line-function 'rebac-schema-indent-line)
  (setq-local indent-tabs-mode t))


;;;###autoload
(add-to-list 'auto-mode-alist '("\\.schema" . rebac-schema-mode))

(defvar rebac-schema-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map "C-c c" #'do-stuff)
    ...
    map)) ; don’t forget to return the map here!
