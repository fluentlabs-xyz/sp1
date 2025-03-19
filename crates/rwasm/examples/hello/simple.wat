(module
     (func $main
        i32.const 7
        call $fib
        drop
        )
     (func $fib  (param $n i32) (result i32)
    local.get $n
    i32.const 2
    i32.add
    return
  )
  (export "main" (func $main)))