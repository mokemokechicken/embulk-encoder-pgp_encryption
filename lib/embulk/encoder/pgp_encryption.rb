Embulk::JavaPlugin.register_encoder(
  "pgp_encryption", "org.embulk.encoder.pgp_encryption.PgpEncryptionEncoderPlugin",
  File.expand_path('../../../../classpath', __FILE__))
