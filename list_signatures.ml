(* list_signatures.ml - Extract and save signature patterns *)

module F = Format
module YS = Yojson.Safe
module YU = Yojson.Safe.Util

(* Abstract trace element type for pattern matching *)
type abstract_elem =
  | INPUT
  | STORE
  | CONVERT      (* BinOp, UnOp, Cast operations *)
  | PRUNE
  | CALL
  | LIBRARY_CALL
  | INT_OVERFLOW
  | INT_UNDERFLOW
  | FORMAT_STRING
  | CMD_INJECTION
  | BUFFER_OVERFLOW
  | ALLOCATE
  | FREE
  | MULTIPLY     (* For IntOverflow with multiplication *)
  | UNKNOWN
[@@deriving show, yojson]

(* Signature info to save *)
type signature_info = {
  bug_type: string;
  qualifier: string;
  severity: string;
  abstract_traces: abstract_elem list list;
}
[@@deriving yojson]

(* Convert feature JSON to abstract element *)
let abstract_of_feature (feature_str : string) : abstract_elem =
  try
    let feature_json = YS.from_string feature_str in
    match feature_json with
    | `List (`String "Input" :: _) -> INPUT
    | `List (`String "Store" :: _) -> STORE
    | `List (`String "BinOp" :: `String "*" :: _) -> MULTIPLY
    | `List (`String "BinOp" :: _) -> CONVERT
    | `List (`String "UnOp" :: _) -> CONVERT
    | `List (`String "Cast" :: _) -> CONVERT
    | `List (`String "Prune" :: _) -> PRUNE
    | `List (`String "Call" :: _) -> CALL
    | `List (`String "LibraryCall" :: _) -> LIBRARY_CALL
    | `List (`String "IntOverflow" :: _) -> INT_OVERFLOW
    | `List (`String "IntUnderflow" :: _) -> INT_UNDERFLOW
    | `List (`String "FormatString" :: _) -> FORMAT_STRING
    | `List (`String "CmdInjection" :: _) -> CMD_INJECTION
    | `List (`String "BufferOverflow" :: _) -> BUFFER_OVERFLOW
    | `List (`String "Allocate" :: _) -> ALLOCATE
    | `List (`String "Free" :: _) -> FREE
    | _ -> UNKNOWN
  with _ -> UNKNOWN

(* Convert a trace (list of steps) to abstract trace *)
let abstract_trace (trace_json : YS.t) : abstract_elem list =
  match trace_json with
  | `List steps ->
      List.filter_map (fun step ->
        try
          let feature_str = step |> YU.member "feature" |> YU.to_string in
          let abstract_elem = abstract_of_feature feature_str in
          Some abstract_elem
        with _ -> None
      ) steps
  | _ -> []

(* Process a single signature JSON file *)
let process_signature_file (json_path : string) : signature_info option =
  try
    let json = YS.from_file json_path in
    let bug_type = json |> YU.member "bug_type" |> YU.to_string in
    let qualifier = json |> YU.member "qualifier" |> YU.to_string in
    let severity = json |> YU.member "severity" |> YU.to_string in
    let bug_traces = json |> YU.member "bug_trace" |> YU.to_list in
    
    let abstract_traces = List.map abstract_trace bug_traces in
    
    Some { bug_type; qualifier; severity; abstract_traces }
  with e ->
    F.eprintf "Error processing %s: %s\n" json_path (Printexc.to_string e);
    None

(* Save signature info to output file *)
let save_signature_info (output_path : string) (info : signature_info) : unit =
  try
    (* Create parent directories if needed *)
    let rec mkdir_p dir =
      if not (Sys.file_exists dir) then (
        mkdir_p (Filename.dirname dir);
        Unix.mkdir dir 0o755
      )
    in
    mkdir_p (Filename.dirname output_path);
    
    (* Save JSON *)
    let json = signature_info_to_yojson info in
    YS.to_file output_path json;
    F.printf "Saved: %s\n" output_path
  with e ->
    F.eprintf "Error saving %s: %s\n" output_path (Printexc.to_string e)

(* Process all signatures in a directory *)
let process_directory (sig_db_dir : string) (output_dir : string) : unit =
  (* Get all subdirectories *)
  let subdirs = 
    Sys.readdir sig_db_dir
    |> Array.to_list
    |> List.filter (fun name ->
         let path = Filename.concat sig_db_dir name in
         Sys.is_directory path
       )
  in
  
  (* Process each subdirectory *)
  List.iter (fun subdir ->
    F.printf "Processing %s...\n" subdir;
    let subdir_path = Filename.concat sig_db_dir subdir in
    let output_subdir = Filename.concat output_dir subdir in
    
    (* Get all JSON files in subdirectory *)
    let json_files =
      Sys.readdir subdir_path
      |> Array.to_list
      |> List.filter (fun name -> Filename.check_suffix name ".json")
    in
    
    (* Process each JSON file *)
    List.iter (fun json_file ->
      let input_path = Filename.concat subdir_path json_file in
      let output_path = Filename.concat output_subdir json_file in
      
      match process_signature_file input_path with
      | Some info -> save_signature_info output_path info
      | None -> ()
    ) json_files
  ) subdirs

(* Main entry point *)
let run (sig_db_dir : string) : unit =
  let output_dir = "signature-db-info" in
  F.printf "Reading signatures from: %s\n" sig_db_dir;
  F.printf "Writing abstract patterns to: %s\n" output_dir;
  F.printf "\n";
  
  process_directory sig_db_dir output_dir;
  
  F.printf "\nDone!\n"
