open Core_kernel
open Bap_future.Std
open Bap.Std
open Regular.Std
open Format
open Option.Monad_infix
include Self()

(* Returns Yojson.Basic.t *)
(* Format like:
  [{
    "name": "imp.gethostname",
    "demname": "",
    "flagname": "sym.imp.gethostname",
    "ordinal": 108,
    "bind": "GLOBAL",
    "size": 16,
    "type": "FUNC",
    "vaddr": 19776,
    "paddr": 19776
   }]
    *)
let r2_get_symbols r2 =
    R2.command_json ~r2 "isj"

(* Returns Yojson.Basic.t *)
(* Format like:
  [{
    "name": ".bss",
    "size": 0,
    "vsize": 4760,
    "perm": "-rw-",
    "paddr": 139848,
    "vaddr": 143968
  }]

 *)

let r2_get_sections r2 =
    R2.command_json ~r2 "iSj"


(* Returns Yojson.Basic.t *)
(* Format like:
  [{
    "offset": 16384,
    "name": "fcn.00004000",
    "size": 27,
    "is-pure": "false",
    "realsz": 27,
    "stackframe": 8,
    "calltype": "amd64",
    "cost": 13,
    ...
  }]
 *)
let r2_get_functions r2 =
    R2.command_json ~r2 "aaa;aflj"

let get_symbols json =
    match json with
    | `List l ->
        List.filter_map ~f:(fun item ->
            match item with
            | `Assoc items -> (
                let name, paddr = List.fold ~f:(fun (k, v) acc ->
                    match k with
                    | "name" ->
                        match acc with
                        | "", a -> v, a
                        | _, _ -> acc
                    | "paddr" ->
                        match acc with
                        | n, "" -> n, v
                        | _, _ -> acc
                    | _ -> None
                ) ~init:("", "") items in
                Some (name, paddr)
            )
            | _ -> None
        ) l
    | _ -> []

let run_radare2 arch file =
  let r2 = R2.open_file file in
  let names = Addr.Table.create () in
  let width = Arch.addr_size arch |> Size.in_bits in
  let add (name,addr) =
    Hashtbl.set names ~key:(Addr.of_int64 ~width (Int64.of_string addr)) ~data:name
  in
  let json = r2_get_symbols r2 in
  let () = List.map ~f:add (get_symbols json) in
  if Hashtbl.length names = 0
  then warning "failed to obtain symbols";
  Ok (Symbolizer.create (Hashtbl.find names))

let main () =
  Stream.merge Project.Info.arch Project.Info.file ~f:run_radare2 |>
  Symbolizer.Factory.register name

let () =
  Config.manpage [
    `S "DESCRIPTION";
    `P "This plugin provides a symbolizer based on radare2.";
    `S  "EXAMPLES";
    `P  "To view the symbols after running the plugin:";
    `P  "$(b, bap --symbolizer=radare2 --dump-symbols) $(i,executable)";
    `P  "To use the internal extractor and *not* this plugin:";
    `P  "$(b, bap --symbolizer=internal --dump-symbols) $(i,executable)";
    `S  "SEE ALSO";
    `P  "$(b,bap-plugin-ida)(1)"
  ];
  Config.when_ready (fun _ -> main ())
