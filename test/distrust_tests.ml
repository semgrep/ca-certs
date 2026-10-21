(** Offline key-distrust regressions against X509 at a fixed, valid time. *)

let read path = Bos.OS.File.read (Fpath.v ("fixtures/" ^ path)) |> Result.get_ok

let certs path =
  X509.Certificate.decode_pem_multiple (read path) |> Result.get_ok

let host name = Some Domain_name.(of_string_exn name |> host_exn)

let time () =
  let t, _, _ = Ptime.of_rfc3339 "2026-10-22T12:00:00Z" |> Result.get_ok in
  Some t

let accepted = function Ok (Some _) -> true | _ -> false

let check label expected result =
  Alcotest.(check bool) label expected (accepted result)

let rejected label result =
  match result with
  | Error `InvalidChain -> ()
  | _ -> Alcotest.fail (label ^ ": expected key rejection")

let variants () =
  let impacted = certs "impacted.pem" in
  Alcotest.(check int) "certificate variants" 16 (List.length impacted);
  let hashes =
    List.map
      (fun cert ->
        X509.Certificate.public_key cert
        |> X509.Public_key.fingerprint ~hash:`SHA256
        |> Ohex.encode)
      impacted
    |> List.sort_uniq String.compare
  in
  Alcotest.(check int) "distinct keys" 8 (List.length hashes);
  List.iter
    (fun cert ->
      Alcotest.(check bool) "blocked variant" true (Distrust.blocked cert))
    impacted;
  (* An unrelated cross-signing root must remain usable. *)
  List.iter
    (fun cert ->
      Alcotest.(check bool) "unaffected root" false (Distrust.blocked cert))
    (certs "roots.pem")

let paths () =
  let anchors = certs "roots.pem" in
  List.iter
    (fun stem ->
      let chain = certs (stem ^ ".pem") in
      let host = host (stem ^ ".we-have-a-problem.com") in
      check (stem ^ " baseline") true
        (X509.Authenticator.chain_of_trust ~time anchors ~host chain);
      rejected (stem ^ " supplied chain")
        (Distrust.authenticator ~time anchors ~host chain);
      match chain with
      | leaf :: intermediate :: _ ->
          check "custom intermediate baseline" true
            (X509.Authenticator.chain_of_trust ~time [ intermediate ] ~host
               [ leaf ]);
          rejected "custom intermediate anchor"
            (Distrust.authenticator ~time [ intermediate ] ~host [ leaf ])
      | _ -> Alcotest.fail "missing intermediate")
    [ "dv-g3b-emudhra"; "dv-g3b-aaa-emudhra" ]

let enterprise () =
  let chain = certs "enterprise-leaf.pem" in
  let anchors = certs "enterprise-root.pem" in
  let verify = Distrust.authenticator ~time anchors in
  check "enterprise root" true (verify ~host:(host "localhost") chain);
  check "hostname validation" false (verify ~host:(host "wrong.example") chain);
  check "allowed SHA256" true
    (Distrust.authenticator ~time ~allowed_hashes:[ `SHA256 ] anchors
       ~host:(host "localhost") chain);
  check "allowed hashes" false
    (Distrust.authenticator ~time ~allowed_hashes:[] anchors
       ~host:(host "localhost") chain);
  (* A blocked extra certificate must not be silently discarded. *)
  rejected "blocked extraneous certificate"
    (verify ~host:(host "localhost") (chain @ certs "impacted.pem"))

let public_authenticator () =
  if Sys.win32 then ()
  else begin
    (* A separate process owns these environment overrides. *)
    Unix.putenv "SSL_CERT_FILE" "fixtures/roots.pem";
    Unix.putenv "NIX_SSL_CERT_FILE" "fixtures/roots.pem";
    Unix.putenv "OCAML_EXTRA_CA_CERTS" "fixtures/impacted.pem";
    let raw = Ca_certs.trust_anchors () |> Result.get_ok in
    Alcotest.(check string)
      "raw anchors are unfiltered"
      (read "roots.pem" ^ "\n" ^ read "impacted.pem")
      raw;
    let verify = Ca_certs.authenticator () |> Result.get_ok in
    let chain = certs "dv-g3b-emudhra.pem" in
    let leaf = List.hd chain in
    rejected "custom files cannot restore a blocked anchor"
      (verify ~host:(host "dv-g3b-emudhra.we-have-a-problem.com") [ leaf ])
  end

let () =
  Alcotest.run "key distrust"
    [
      ( "offline",
        [
          Alcotest.test_case "16 variants, 8 keys" `Quick variants;
          Alcotest.test_case "direct and cross-signed paths" `Quick paths;
          Alcotest.test_case "enterprise validation" `Quick enterprise;
          Alcotest.test_case "public authenticator custom files" `Quick
            public_authenticator;
        ] );
    ]
