open Core_kernel

type ins = [
  | `IN8
  | `IN16
  | `IN32
] [@@deriving bin_io, sexp, compare, enumerate]


