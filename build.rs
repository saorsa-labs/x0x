fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=X0X_UPGRADE_TEST_PUBLIC_KEY");
    #[cfg(feature = "upgrade-test-signing")]
    {
        if std::env::var("PROFILE")? == "release" {
            return Err(std::io::Error::other(
                "upgrade-test-signing is forbidden in the release profile",
            )
            .into());
        }
        provision_test_key()?;
    }
    Ok(())
}

#[cfg(feature = "upgrade-test-signing")]
fn provision_test_key() -> Result<(), Box<dyn std::error::Error>> {
    use fips204::traits::SerDes;

    let public = if let Some(path) = std::env::var_os("X0X_UPGRADE_TEST_PUBLIC_KEY") {
        println!(
            "cargo:rerun-if-changed={}",
            std::path::Path::new(&path).display()
        );
        std::fs::read(path)?
    } else {
        // All-features lint/doc builds need no signing secret. Generate a fresh
        // key and discard the secret; private rehearsals supply their public key.
        let (public, _secret) = fips204::ml_dsa_65::try_keygen().map_err(std::io::Error::other)?;
        public.into_bytes().to_vec()
    };
    let bytes: [u8; 1952] = public.try_into().map_err(|_| {
        std::io::Error::other("test signing public key must contain exactly 1952 bytes")
    })?;
    fips204::ml_dsa_65::PublicKey::try_from_bytes(bytes).map_err(std::io::Error::other)?;
    let output = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR").ok_or_else(|| std::io::Error::other("OUT_DIR is missing"))?,
    );
    std::fs::write(output.join("upgrade-test-signing-public-key.bin"), bytes)?;
    Ok(())
}
