#' Clase R6 para conexión a MySQL vía túnel SSH
#'
#' @export 
ConexionBD <- R6::R6Class(
  "ConexionBD",

  private = list(
    bg_tunnel = NULL,

    find_free_port = function() {
      for (port in sample(32768L:49151L, 50L)) {
        ok <- tryCatch({
          s <- serverSocket(port)
          close(s)
          TRUE
        }, error = function(e) FALSE)
        if (ok) return(port)
      }
      tryCatch({
        cmd  <- if (.Platform$OS.type == "windows") "netstat" else "ss"
        args <- if (.Platform$OS.type == "windows") c("-a", "-n") else c("-tln")
        out  <- suppressWarnings(system2(cmd, args, stdout = TRUE, stderr = FALSE))
        if (is.character(out) && length(out) > 0L) {
          used <- unique(as.integer(unlist(
            regmatches(out, gregexpr("(?<=:)\\d+(?=\\s|$)", out, perl = TRUE))
          )))
          used      <- used[!is.na(used) & used > 0L]
          candidates <- setdiff(32768L:49151L, used)
          if (length(candidates) > 0L) return(sample(candidates, 1L))
        }
      }, error = function(e) NULL)
      sample(32768L:49151L, 1L)
    },

    parse_env_file = function(path) {
      lines <- readLines(path, warn = FALSE)
      lines <- lines[nzchar(trimws(lines)) & !startsWith(trimws(lines), "#")]
      for (line in lines) {
        idx <- regexpr("=", line, fixed = TRUE)
        if (idx > 0) {
          key <- trimws(substr(line, 1, idx - 1))
          val <- trimws(substr(line, idx + 1, nchar(line)))
          val <- gsub('^["\']|["\']$', "", val)
          if (nzchar(key)) do.call(Sys.setenv, setNames(list(val), key))
        }
      }
    }
  ),

  public = list(
    path_env   = NULL,
    con        = NULL,
    local_port = NULL,

    initialize = function(path_env) {
      self$path_env <- path_env
    },

    conectar = function(db_name) {
      # 1. Validar que exista el archivo de credenciales
      if (!file.exists(self$path_env)) {
        stop(paste("No existe el archivo:", self$path_env))
      }

      # 2. Cargar variables con override
      private$parse_env_file(self$path_env)

      required_vars <- c(
        "SSH_HOST", "SSH_PORT", "SSH_USER", "SSH_KEY_FILE",
        "SSH_KEY_PASSPHRASE", "REMOTE_DB_HOST", "REMOTE_DB_PORT",
        "DB_USER", "DB_PASS"
      )

      missing_vars <- required_vars[!nzchar(Sys.getenv(required_vars))]
      if (length(missing_vars) > 0) {
        stop(paste("Faltan variables en el archivo:", paste(missing_vars, collapse = ", ")))
      }

      ssh_host           <- Sys.getenv("SSH_HOST")
      ssh_port           <- as.integer(Sys.getenv("SSH_PORT"))
      ssh_user           <- Sys.getenv("SSH_USER")
      ssh_key_file       <- Sys.getenv("SSH_KEY_FILE")
      ssh_key_passphrase <- Sys.getenv("SSH_KEY_PASSPHRASE")
      remote_db_host     <- Sys.getenv("REMOTE_DB_HOST")
      remote_db_port     <- as.integer(Sys.getenv("REMOTE_DB_PORT"))
      local_bind_host    <- ifelse(nzchar(Sys.getenv("LOCAL_BIND_HOST")),
                                   Sys.getenv("LOCAL_BIND_HOST"), "127.0.0.1")
      db_user            <- Sys.getenv("DB_USER")
      db_pass            <- Sys.getenv("DB_PASS")

      # 3. Construir ruta del PEM relativa al archivo de credenciales
      base_dir     <- dirname(normalizePath(self$path_env))
      ssh_key_path <- file.path(base_dir, ssh_key_file)

      if (!file.exists(ssh_key_path)) {
        stop(paste("No existe el archivo PEM:", ssh_key_path))
      }

      # 4. Crear túnel SSH en proceso background
      self$local_port <- private$find_free_port()

      private$bg_tunnel <- callr::r_bg(
        function(ssh_user, ssh_host, ssh_port, ssh_key_path,
                 ssh_key_passphrase, remote_db_host, remote_db_port, local_port) {
          session <- ssh::ssh_connect(
            host    = paste0(ssh_user, "@", ssh_host, ":", ssh_port),
            keyfile = ssh_key_path,
            passwd  = ssh_key_passphrase
          )
          on.exit(ssh::ssh_disconnect(session))
          ssh::ssh_tunnel(
            session,
            port   = local_port,
            target = paste0(remote_db_host, ":", remote_db_port)
          )
        },
        args = list(
          ssh_user           = ssh_user,
          ssh_host           = ssh_host,
          ssh_port           = ssh_port,
          ssh_key_path       = ssh_key_path,
          ssh_key_passphrase = ssh_key_passphrase,
          remote_db_host     = remote_db_host,
          remote_db_port     = remote_db_port,
          local_port         = self$local_port
        )
      )

      Sys.sleep(4)

      # 5. Conectar y validar
      tryCatch({
        self$con <- DBI::dbConnect(
          RMariaDB::MariaDB(),
          host     = local_bind_host,
          port     = self$local_port,
          dbname   = db_name,
          username = db_user,
          password = db_pass
        )

        DBI::dbGetQuery(self$con, "SELECT 1")
        message(paste("Conectado a base:", db_name))
        return(invisible(self$con))

      }, error = function(e) {
        self$cerrar()
        stop(paste0("La base '", db_name, "' no existe o las credenciales son invalidas."))
      })
    },

    cerrar = function() {
      if (!is.null(self$con)) {
        tryCatch(DBI::dbDisconnect(self$con), error = function(e) invisible(NULL))
        self$con <- NULL
        message("Conexion cerrada")
      }
      if (!is.null(private$bg_tunnel)) {
        tryCatch(private$bg_tunnel$kill(), error = function(e) invisible(NULL))
        private$bg_tunnel <- NULL
        message("Tunel SSH cerrado")
      }
    }
  )
)
