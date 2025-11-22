(* tracer_list.ml - Standalone tool to list and extract signature patterns *)

(* Include the list_signatures module functionality *)
module F = Format

let () =
  (* Parse command line arguments *)
  let sig_db_dir = ref "" in
  let specs = [
    ("--db", Arg.Set_string sig_db_dir, "Signature database directory");
  ] in
  let usage = "Usage: tracer list --db <signature-db-dir>" in
  
  Arg.parse specs (fun _ -> ()) usage;
  
  if !sig_db_dir = "" then (
    F.eprintf "Error: --db option is required\n";
    Arg.usage specs usage;
    exit 1
  );
  
  (* Check if directory exists *)
  if not (Sys.file_exists !sig_db_dir && Sys.is_directory !sig_db_dir) then (
    F.eprintf "Error: Directory not found: %s\n" !sig_db_dir;
    exit 1
  );
  
  (* Run the list signatures process *)
  List_signatures.run !sig_db_dir
