(** Incident-specific key distrust, applied before and after X509 path
    validation. *)

(* SHA256 of DER SubjectPublicKeyInfo, including cross-signed variants:
   https://github.com/galadran/we-have-a-problem.com/blob/8c27813eb898bd6f836da49a01f5e78b9cb6337a/impacted-intermediates.json *)
let blocked_spki_sha256 =
  [
    (* EM DV TLS CA - G3B *)
    "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105";
    (* EM OV TLS CA - G3B *)
    "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b";
    (* EM EV TLS CA - G3B *)
    "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41";
    (* EM DV TLS CA - G3C *)
    "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f";
    (* EM OV TLS CA - G3C *)
    "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8";
    (* EM EV TLS CA - G3C *)
    "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0";
    (* EM OV CS CA - G3B *)
    "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6";
    (* EM OV CS CA - G3C *)
    "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30";
  ]

let blocked cert =
  let hash =
    X509.Certificate.public_key cert
    |> X509.Public_key.fingerprint ~hash:`SHA256
    |> Ohex.encode
  in
  List.mem hash blocked_spki_sha256

let authenticator ~time ?crls ?allowed_hashes anchors =
  let anchors = List.filter (fun cert -> not (blocked cert)) anchors in
  let verify =
    X509.Authenticator.chain_of_trust ~time ?crls ?allowed_hashes anchors
  in
  fun ?ip ~host certs ->
    (* Dropping a presented certificate could conceal a compromised path. *)
    if List.exists blocked certs then Error `InvalidChain
    else
      match verify ?ip ~host certs with
      | Ok (Some (chain, anchor)) when List.exists blocked (anchor :: chain) ->
          Error `InvalidChain
      | result -> result
