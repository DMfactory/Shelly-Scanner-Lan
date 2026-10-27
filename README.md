Esegue una scansione della rete e identifica gli shelly trovati dal nome device mac address e modello, controlla anche la presenza di aggiornamenti


  Scanner Shelly - cerca i dispositivi Shelly su una classe C (es. 192.168.1.x)
  e mostra il nome impostato dall'utente.
 
  Gen1  : GET /shelly (identificazione) + GET /settings (nome)
  Gen2+ : GET /shelly (include già il nome), fallback su /rpc/Sys.GetConfig
 
  Aggiornamenti firmware (solo canale stabile):
  Gen1  : GET /ota (has_update / new_version), con "forza controllo" anche /ota/check
  Gen2+ : GET /rpc/Shelly.CheckForUpdate (chiave "stable")
 
  Requisiti: PHP con estensione curl, server nella stessa rete dei Shelly.
 
