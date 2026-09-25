use serde_json::Value;

pub fn answer(session: &Value, locale: &str) -> String {
    let count = session["assessment"]["signals"]
        .as_array()
        .map_or(0, Vec::len);
    let index = match locale {
        "es" => 1,
        "de" => 2,
        "fr" => 3,
        _ => 0,
    };
    let no_signals = [
        "No configured text signal was recorded. This does not exclude fraud.",
        "No se registró ninguna señal de texto configurada. Esto no descarta el fraude.",
        "Es wurde kein konfigurierter Texthinweis erfasst. Dies schließt Betrug nicht aus.",
        "Aucun signal textuel configuré n’a été enregistré. Cela n’exclut pas une fraude.",
    ];
    let recorded = [
        "Recorded signals",
        "Señales registradas",
        "Erfasste Hinweise",
        "Signaux enregistrés",
    ];
    let explanation = [
        "The saved observations explain why review is needed; they do not prove authenticity, safety or fraud. Review each signal in this session and verify the person through a known number or official app. Never share passwords or recovery secrets.",
        "Las observaciones guardadas explican la necesidad de revisión; no demuestran autenticidad, seguridad ni fraude. Revisa cada señal de esta sesión y verifica a la persona por un número conocido o una app oficial. Nunca compartas contraseñas ni secretos de recuperación.",
        "Die gespeicherten Beobachtungen erklären den Prüfbedarf; sie beweisen weder Echtheit noch Sicherheit oder Betrug. Prüfe jeden Hinweis dieser Sitzung und verifiziere die Person über eine bekannte Nummer oder offizielle App. Teile niemals Passwörter oder Wiederherstellungsgeheimnisse.",
        "Les observations enregistrées expliquent le besoin de vérification ; elles ne prouvent ni l’authenticité, ni la sécurité, ni la fraude. Examinez chaque signal de cette session et vérifiez la personne par un numéro connu ou une application officielle. Ne partagez jamais de mots de passe ou de secrets de récupération.",
    ];
    let lead = if count == 0 {
        no_signals[index].to_owned()
    } else {
        format!("{}: {count}.", recorded[index])
    };
    format!("{lead} {}", explanation[index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn generated_explanations_use_requested_language() {
        let session = json!({"assessment":{"signals":[]}});
        for (locale, phrase) in [
            ("en", "No configured"),
            ("es", "No se registró"),
            ("de", "Es wurde"),
            ("fr", "Aucun signal"),
        ] {
            assert!(answer(&session, locale).starts_with(phrase));
        }
    }
}
